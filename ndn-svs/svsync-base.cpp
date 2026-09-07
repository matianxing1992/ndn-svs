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
#include <ndn-cxx/util/logger.hpp>

namespace ndn::svs {

NDN_LOG_INIT(ndn_svs.SVSyncBase);

SVSyncBase::SVSyncBase(const Name& syncPrefix,
                       const Name& dataPrefix,
                       const NodeID& id,
                       ndn::Face& face,
                       const UpdateCallback& updateCallback,
                       const SecurityOptions& securityOptions,
                       std::shared_ptr<DataStore> dataStore,
                       const SyncProtocolOptions& protocolOptions)
  : m_syncPrefix(syncPrefix)
  , m_dataPrefix(dataPrefix)
  , m_securityOptions(securityOptions)
  , m_id(id)
  , m_face(face)
  , m_fetcher(face, securityOptions)
  , m_onUpdate(updateCallback)
  , m_dataStore(std::move(dataStore))
  , m_core(m_face, m_syncPrefix, m_onUpdate, securityOptions, m_id, protocolOptions)
{
  // Register new data store
  if (m_dataStore == DEFAULT_DATASTORE)
    m_dataStore = std::make_shared<MemoryDataStore>();

  // Register data prefix
  m_registeredDataPrefix = m_face.setInterestFilter(
    m_dataPrefix, std::bind(&SVSyncBase::onDataInterest, this, _2), [](auto&&...) {});
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
  NodeID pubId = id != EMPTY_NODE_ID ? id : m_id;
  SeqNo newSeq = m_core.getSeqNo(pubId) + 1;

  publishDataAtSeq(content, freshness, pubId, newSeq, contentType);
  return newSeq;
}

void
SVSyncBase::publishDataAtSeq(const Block& content, const ndn::time::milliseconds& freshness,
                             const NodeID& nid, const SeqNo seq, uint32_t contentType)
{
  NodeID pubId = nid != EMPTY_NODE_ID ? nid : m_id;
  insertDataAtSeq(content, freshness, pubId, seq, contentType);
  m_core.updateSeqNo(seq, pubId);
}

void
SVSyncBase::insertDataAtSeq(const Block& content, const ndn::time::milliseconds& freshness,
                            const NodeID& nid, const SeqNo seq, uint32_t contentType)
{
  NodeID pubId = nid != EMPTY_NODE_ID ? nid : m_id;
  Name dataName = getDataName(pubId, m_core.getBootstrapTime(), seq);
  auto data = std::make_shared<Data>(dataName);
  data->setContent(content);
  data->setFreshnessPeriod(freshness);
  data->setContentType(contentType);

  m_securityOptions.dataSigner->sign(*data);

  {
    std::lock_guard<std::mutex> lock(m_dataStoreMutex);
    m_dataStore->insert(*data);
  }
  m_face.put(*data);
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
  Name dataName = getDataName(nid, m_core.getBootstrapTime(), seq).appendVersion(0).appendSegment(segNo);
  auto data = std::make_shared<Data>(dataName);
  data->setContent(content);
  data->setFreshnessPeriod(freshness);
  data->setContentType(contentType);
  data->setFinalBlock(finalBlock);
  m_securityOptions.dataSigner->sign(*data);
  {
    std::lock_guard<std::mutex> lock(m_dataStoreMutex);
    m_dataStore->insert(*data);
  }
}

void
SVSyncBase::insertPreparedData(const Data& data, bool putToFace)
{
  auto preparedData = std::make_shared<Data>(data);
  {
    std::lock_guard<std::mutex> lock(m_dataStoreMutex);
    m_dataStore->insert(*preparedData);
  }
  if (putToFace) {
    m_face.put(*preparedData);
  }
}

void
SVSyncBase::insertPreparedDataBatch(const std::vector<Data>& packets)
{
  if (!packets.empty() && !m_dataStore->supportsErase()) {
    throw std::logic_error("DataStore does not support transactional rollback");
  }

  // Force every final encoding before the first irreversible store mutation.
  for (const auto& packet : packets) {
    if (packet.wireEncode().size() > MAX_NDN_PACKET_SIZE) {
      throw std::length_error("prepared SVS Data exceeds MAX_NDN_PACKET_SIZE");
    }
  }

  std::vector<Name> inserted;
  inserted.reserve(packets.size());
  try {
    std::lock_guard<std::mutex> lock(m_dataStoreMutex);
    for (const auto& packet : packets) {
      // ndn-cxx InMemoryStorage obtains Data::shared_from_this() during
      // insertion, so the exact object passed here must have a shared owner.
      auto ownedPacket = std::make_shared<Data>(packet);
      m_dataStore->insert(*ownedPacket);
      inserted.push_back(packet.getName());
    }
  }
  catch (...) {
    auto insertionFailure = std::current_exception();
    try {
      std::lock_guard<std::mutex> lock(m_dataStoreMutex);
      for (auto it = inserted.rbegin(); it != inserted.rend(); ++it) {
        m_dataStore->erase(*it);
      }
    }
    catch (...) {
      throw std::runtime_error("DataStore rollback failed after partial insertion");
    }
    std::rethrow_exception(insertionFailure);
  }
}

bool
SVSyncBase::removePreparedDataBatch(const std::vector<Data>& packets) noexcept
{
  try {
    if (!packets.empty() && !m_dataStore->supportsErase()) {
      return false;
    }
    std::lock_guard<std::mutex> lock(m_dataStoreMutex);
    for (auto it = packets.rbegin(); it != packets.rend(); ++it) {
      m_dataStore->erase(it->getName());
    }
    return true;
  }
  catch (...) {
    return false;
  }
}

void
SVSyncBase::putPreparedData(const Data& data)
{
  if (m_preparedDataPutHook) {
    m_preparedDataPutHook(data);
  }
  m_face.put(data);
}

void
SVSyncBase::onDataInterest(const Interest& interest)
{
  const auto lookupStart = std::chrono::steady_clock::now();
  const auto lookupStartNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
    lookupStart.time_since_epoch()).count();
  const auto nonce = interest.getNonce();
  NDN_LOG_TRACE("event=producer_interest"
                << " name=" << interest.getName()
                << " nonce=" << nonce
                << " mono_ns=" << lookupStartNs);
  std::shared_ptr<const Data> data;
  {
    std::lock_guard<std::mutex> lock(m_dataStoreMutex);
    data = m_dataStore->find(interest);
  }
  const auto lookupUs = std::chrono::duration_cast<std::chrono::microseconds>(
    std::chrono::steady_clock::now() - lookupStart).count();
  if (data != nullptr) {
    NDN_LOG_TRACE("event=producer_store_hit"
                  << " name=" << interest.getName()
                  << " nonce=" << nonce
                  << " mono_ns=" << lookupStartNs
                  << " lookup_us=" << lookupUs
                  << " data_name=" << data->getName());
    m_face.put(*data);
    NDN_LOG_TRACE("event=producer_data_put"
                  << " name=" << interest.getName()
                  << " nonce=" << nonce
                  << " mono_ns=" << std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::steady_clock::now().time_since_epoch()).count()
                  << " data_name=" << data->getName());
  }
  else {
    NDN_LOG_TRACE("event=producer_store_miss"
                  << " name=" << interest.getName()
                  << " nonce=" << nonce
                  << " mono_ns=" << lookupStartNs
                  << " lookup_us=" << lookupUs);
  }
}

void
SVSyncBase::fetchData(const NodeID& nid,
                      const SeqNo& seqNo,
                      const DataValidatedCallback& onValidated,
                      int nRetries)
{
  DataValidationErrorCallback onValidationFailed =
    std::bind(&SVSyncBase::onDataValidationFailed, this, _1, _2);
  TimeoutCallback onTimeout = [](auto&&...) {};
  fetchData(nid, m_core.getBootstrapTime(), seqNo, onValidated, onValidationFailed, onTimeout, nRetries);
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
                      const SeqNo& seqNo,
                      const DataValidatedCallback& onValidated,
                      const DataValidationErrorCallback& onValidationFailed,
                      const TimeoutCallback& onTimeout,
                      int nRetries)
{
  fetchData(nid, m_core.getBootstrapTime(), seqNo, onValidated, onValidationFailed, onTimeout, nRetries);
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
  interest.setInterestLifetime(m_fetchInterestLifetime);

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
  if (shouldCache(data)) {
    std::lock_guard<std::mutex> lock(m_dataStoreMutex);
    m_dataStore->insert(data);
  }

  dataCallback(data);
}

void
SVSyncBase::onDataValidationFailed(const Data& data, const ValidationError& error)
{
}

} // namespace ndn::svs
