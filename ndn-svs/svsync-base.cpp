/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2025 University of California, Los Angeles
 *
 * This file is part of ndn-svs, synchronization library for distributed realtime
 * applications for NDN.
 *
 * ndn-svs library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, in version 2.1 of the License.
 *
 * ndn-svs library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 */

#include "svsync-base.hpp"
#include "store-memory.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

#include <algorithm>
#include <limits>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

namespace ndn::svs {

SVSyncBase::SVSyncBase(const Name& syncPrefix,
                       const Name& dataPrefix,
                       const NodeID& id,
                       ndn::Face& face,
                       const UpdateCallback& updateCallback,
                       const SecurityOptions& securityOptions,
                       std::shared_ptr<DataStore> dataStore,
                       std::optional<BootstrapTime> bootstrapTime)
  : m_syncPrefix(syncPrefix)
  , m_dataPrefix(dataPrefix)
  , m_securityOptions(securityOptions)
  , m_id(id)
  , m_face(face)
  , m_fetcher(face, securityOptions)
  , m_onUpdate(updateCallback)
  , m_dataStore(std::move(dataStore))
  , m_core(m_face, m_syncPrefix, m_onUpdate, securityOptions, m_id, bootstrapTime)
{
  // Register new data store
  if (m_dataStore == DEFAULT_DATASTORE)
    m_dataStore = std::make_shared<MemoryDataStore>();

  // Register data prefix
  const std::weak_ptr<int> lifetime = m_lifetime;
  auto registration = std::make_shared<ndn::RegisteredPrefixHandle>();
  *registration = m_face.setInterestFilter(
    m_dataPrefix,
    [this, lifetime] (const auto&, const Interest& interest) {
      if (!lifetime.expired())
        onDataInterest(interest);
    },
    [lifetime, registration] (auto&&...) {
      if (lifetime.expired())
        registration->unregister();
    },
    [] (auto&&...) {});
  m_registeredDataPrefix = *registration;
}

SeqNo
SVSyncBase::publishData(const uint8_t* buf,
                        size_t len,
                        const ndn::time::milliseconds& freshness,
                        const NodeID& nid)
{
  return publishData(ndn::encoding::makeBinaryBlock(ndn::tlv::Content, { buf, len }), freshness, nid);
}

SeqNo
SVSyncBase::publishData(const Block& content,
                        const ndn::time::milliseconds& freshness,
                        const NodeID& id,
                        uint32_t contentType)
{
  std::lock_guard<std::mutex> lock(m_publicationMutex);
  NodeID pubId = id != EMPTY_NODE_ID ? id : m_id;
  const SeqNo previous = m_core.getSeqNo(pubId);
  if (previous == std::numeric_limits<SeqNo>::max())
    NDN_THROW(std::overflow_error("publication sequence number is exhausted"));
  const SeqNo newSeq = previous + 1;

  auto data =
    prepareDataPacket(content, freshness, pubId, newSeq, std::nullopt, std::nullopt, contentType);
  if (!data)
    NDN_THROW(std::length_error("Data exceeds the packet size limit"));

  m_dataStore->insert(*data);
  m_core.updateSeqNo(newSeq, pubId);
  m_face.put(*data);

  return newSeq;
}

void
SVSyncBase::insertDataSegment(const Block& content,
                              const ndn::time::milliseconds& freshness,
                              const NodeID& nid,
                              const SeqNo seq,
                              const size_t segNo,
                              const Name::Component& finalBlock,
                              uint32_t contentType)
{
  auto data = prepareDataPacket(content, freshness, nid, seq, segNo, finalBlock, contentType);
  if (!data)
    NDN_THROW(std::length_error("Data exceeds the packet size limit"));
  m_dataStore->insert(*data);
}

std::shared_ptr<const Data>
SVSyncBase::prepareDataPacket(const Block& content,
                              time::milliseconds freshness,
                              const NodeID& nid,
                              SeqNo seq,
                              std::optional<size_t> segNo,
                              std::optional<Name::Component> finalBlock,
                              uint32_t contentType,
                              size_t maxPacketSize)
{
  if (segNo.has_value() != finalBlock.has_value())
    NDN_THROW(std::invalid_argument("segment number and FinalBlockId must be specified together"));
  Name dataName = getDataName(nid, m_core.getBootstrapTime(), seq);
  if (segNo)
    dataName.appendVersion(0).appendSegment(*segNo);
  auto data = std::make_shared<Data>(dataName);
  data->setContent(content);
  data->setFreshnessPeriod(freshness);
  data->setContentType(contentType);
  data->setFinalBlock(finalBlock);
  m_securityOptions.dataSigner->sign(*data);
  if (data->wireEncode().size() > std::min(maxPacketSize, ndn::MAX_NDN_PACKET_SIZE))
    return nullptr;
  registerDataPrefix(nid);
  return data;
}

void
SVSyncBase::registerDataPrefix(const NodeID& nid)
{
  const auto prefix = getDataName(nid, m_core.getBootstrapTime(), 1).getPrefix(-2);
  if (m_dataPrefix.isPrefixOf(prefix))
    return;
  std::lock_guard<std::mutex> lock(m_aliasMutex);
  if (!m_registeredAliases.emplace(nid, ndn::ScopedRegisteredPrefixHandle()).second)
    return;
  const std::weak_ptr<int> lifetime = m_lifetime;
  boost::asio::post(m_face.getIoContext(), [this, nid, prefix, lifetime] {
    if (lifetime.expired())
      return;
    std::lock_guard<std::mutex> lock(m_aliasMutex);
    auto registration = std::make_shared<ndn::RegisteredPrefixHandle>();
    *registration = m_face.setInterestFilter(
      prefix,
      [this, lifetime] (const auto&, const Interest& interest) {
        if (!lifetime.expired())
          onDataInterest(interest);
      },
      [lifetime, registration] (auto&&...) {
        if (lifetime.expired())
          registration->unregister();
      },
      [] (auto&&...) {});
    m_registeredAliases.at(nid) = *registration;
  });
}

void
SVSyncBase::onDataInterest(const Interest& interest)
{
  auto data = m_dataStore->find(interest);
  if (data != nullptr)
    m_face.put(*data);
}

void
SVSyncBase::fetchData(const NodeID& nid,
                      const BootstrapTime& bootstrapTime,
                      const SeqNo& seqNo,
                      const DataValidatedCallback& onValidated,
                      int nRetries)
{
  DataValidationErrorCallback onValidationFailed =
    std::bind(&SVSyncBase::onDataValidationFailed, this, _1, _2);
  TimeoutCallback onTimeout = [](auto&&...) {};
  fetchData(nid, bootstrapTime, seqNo, onValidated, onValidationFailed, onTimeout, nRetries);
}

void
SVSyncBase::fetchData(const NodeID& nid,
                      const BootstrapTime& bootstrapTime,
                      const SeqNo& seqNo,
                      const DataValidatedCallback& onValidated,
                      const DataValidationErrorCallback& onValidationFailed,
                      const TimeoutCallback& onTimeout,
                      int nRetries)
{
  Name interestName = getDataName(nid, bootstrapTime, seqNo);
  Interest interest(interestName);
  interest.setCanBePrefix(true);
  interest.setInterestLifetime(2_s);

  m_fetcher.expressInterest(interest,
                            std::bind(&SVSyncBase::onDataValidated, this, _2, onValidated),
                            std::bind(onTimeout, _1), // Nack
                            onTimeout,
                            nRetries,
                            onValidationFailed);
}

void
SVSyncBase::onDataValidated(const Data& data, const DataValidatedCallback& dataCallback)
{
  if (shouldCache(data))
    m_dataStore->insert(data);

  dataCallback(data);
}

void
SVSyncBase::onDataValidationFailed(const Data& data, const ValidationError& error)
{
}

} // namespace ndn::svs
