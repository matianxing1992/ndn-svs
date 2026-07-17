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

#include "svspubsub.hpp"
#include "tlv.hpp"

#include <ndn-cxx/util/segment-fetcher.hpp>
#include <ndn-cxx/util/logger.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <chrono>
#include <set>

namespace ndn::svs {

NDN_LOG_INIT(ndn_svs.SVSPubSub);

namespace {

using SteadyClock = std::chrono::steady_clock;

uint64_t
elapsedUs(const SteadyClock::time_point& begin, const SteadyClock::time_point& end)
{
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count());
}

time::milliseconds
clampDuration(time::milliseconds value,
              time::milliseconds lower,
              time::milliseconds upper)
{
  return std::min(std::max(value, lower), upper);
}

std::chrono::milliseconds
toStdDuration(time::milliseconds value)
{
  return std::chrono::milliseconds(value.count());
}

time::milliseconds
toNdnDuration(std::chrono::steady_clock::duration value)
{
  return time::milliseconds(std::chrono::duration_cast<std::chrono::milliseconds>(value).count());
}

Block
encodeRepairRequests(const std::vector<MissingDataInfo>& requests)
{
  ndn::encoding::EncodingBuffer enc;
  size_t totalLength = 0;

  for (auto it = requests.rbegin(); it != requests.rend(); ++it) {
    size_t entryLength = 0;
    entryLength += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::SeqNo, it->high);
    entryLength += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::SeqNo, it->low);
    entryLength += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::BootstrapTime,
                                                                 it->bootstrapTime);
    entryLength += ndn::encoding::prependBlock(enc, it->nodeId.wireEncode());

    totalLength += enc.prependVarNumber(entryLength);
    totalLength += enc.prependVarNumber(tlv::RepairEntry);
    totalLength += entryLength;
  }

  enc.prependVarNumber(totalLength);
  enc.prependVarNumber(tlv::RepairData);
  return enc.block();
}

std::vector<MissingDataInfo>
decodeRepairRequests(const Block& block)
{
  std::vector<MissingDataInfo> requests;
  block.parse();
  for (const auto& entry : block.elements()) {
    if (entry.type() != tlv::RepairEntry) {
      NDN_THROW(ndn::tlv::Error("RepairEntry", entry.type()));
    }
    entry.parse();
    if (entry.elements().size() != 4 ||
        entry.elements().at(0).type() != ndn::tlv::Name ||
        entry.elements().at(1).type() != tlv::BootstrapTime ||
        entry.elements().at(2).type() != tlv::SeqNo ||
        entry.elements().at(3).type() != tlv::SeqNo) {
      NDN_THROW(ndn::tlv::Error("RepairEntry", entry.type()));
    }

    MissingDataInfo info;
    info.nodeId = NodeID(entry.elements().at(0));
    info.bootstrapTime = ndn::encoding::readNonNegativeInteger(entry.elements().at(1));
    info.low = ndn::encoding::readNonNegativeInteger(entry.elements().at(2));
    info.high = ndn::encoding::readNonNegativeInteger(entry.elements().at(3));
    if (info.low == 0 || info.high < info.low) {
      NDN_THROW(std::invalid_argument("invalid SVS repair sequence range"));
    }
    requests.push_back(std::move(info));
  }
  return requests;
}

} // namespace

SVSPubSub::SVSPubSub(const Name& syncPrefix,
                     const Name& nodePrefix,
                     ndn::Face& face,
                     UpdateCallback updateCallback,
                     const SVSPubSubOptions& options,
                     const SecurityOptions& securityOptions)
  : m_face(face)
  , m_scheduler(face.getIoContext())
  , m_syncPrefix(syncPrefix)
  , m_dataPrefix(nodePrefix)
  , m_onUpdate(std::move(updateCallback))
  , m_opts(options)
  , m_securityOptions(securityOptions)
  , m_svsync(syncPrefix,
             nodePrefix,
             face,
             std::bind(&SVSPubSub::updateCallbackInternal, this, _1),
             securityOptions,
             options.dataStore,
             options.syncProtocol)
  , m_mappingProvider(syncPrefix, nodePrefix, face, securityOptions)
  , m_maxApplicationParametersSize(std::max<size_t>(1, options.maxApplicationParametersSize))
  , m_maxPiggyDataSize(std::max<size_t>(1, options.maxPiggyDataSize))
  , m_piggyDataCacheLimit(std::max<size_t>(1, options.piggyDataCacheLimit))
  , m_asyncPublishAlive(std::make_shared<std::atomic_bool>(true))
{
  m_svsync.setFetchInterestLifetime(
    clampDuration(m_opts.publicationFetchInterestLifetime,
                  m_opts.publicationFetchMinInterestLifetime,
                  m_opts.publicationFetchMaxInterestLifetime));
  m_svsync.setFetchWindowSize(m_opts.publicationFetchWindow);
  m_mappingProvider.setFetchWindowSize(m_opts.mappingFetchWindow);
  m_svsync.getCore().setGetExtraBlocksCallback(
    std::bind(&SVSPubSub::onGetExtraBlocks, this, _1));
  m_svsync.getCore().setRecvExtraBlocksCallback(
    std::bind(&SVSPubSub::onRecvExtraBlocks, this, _1, _2));
}

SVSPubSub::~SVSPubSub()
{
  if (m_asyncPublishAlive) {
    m_asyncPublishAlive->store(false, std::memory_order_relaxed);
  }
  std::vector<std::vector<Data>> unadvertised;
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
    for (const auto& [node, publications] : m_stagedPublicationPackets) {
      for (const auto& [seq, packets] : publications) {
        unadvertised.push_back(packets);
      }
    }
    for (const auto& [node, publications] : m_preparedPublications) {
      for (const auto& [seq, publication] : publications) {
        if (publication.stored) {
          unadvertised.push_back(publication.outerPackets);
        }
      }
    }
    m_stagedPublicationPackets.clear();
    m_preparedPublications.clear();
  }
  for (const auto& packets : unadvertised) {
    if (!m_svsync.removePreparedDataBatch(packets)) {
      NDN_LOG_ERROR("event=async_publish_shutdown_rollback_failed packets=" << packets.size());
    }
  }
}

SeqNo
SVSPubSub::publish(const Name& name,
                   span<const uint8_t> value,
                   const Name& nodePrefix,
                   time::milliseconds freshnessPeriod,
                   std::vector<Block> mappingBlocks)
{
  // A segmented publication is one logical transaction. Serialize its
  // tentative sequence, complete every fallible sign/encode/store operation,
  // and only then expose the sequence to SVS or later callers.
  std::lock_guard<std::mutex> orderLock(m_segmentedPublishMutex);
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo;
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
    auto reserved = m_reservedSeqNo[nid];
    seqNo = std::max(reserved, m_svsync.getCore().getSeqNo(nid)) + 1;
  }

  AsyncPublication publication;
  publication.kind = AsyncPublication::Kind::Bytes;
  publication.bootstrapTime = m_svsync.getCore().getBootstrapTime();
  publication.seqNo = seqNo;
  publication.name = name;
  publication.nodePrefix = nid;
  publication.freshnessPeriod = freshnessPeriod;
  publication.value.assign(value.begin(), value.end());
  publication.mappingBlocks = std::move(mappingBlocks);

  auto prepared = prepareReservedBytes(publication);
  commitPreparedPublication(prepared);
  m_svsync.getCore().updateSeqNo(seqNo, nid);
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
    m_reservedSeqNo[nid] = seqNo;
    m_nextAsyncCommitSeq[nid] = seqNo + 1;
  }
  return seqNo;
}

SeqNo
SVSPubSub::publishAsync(const Name& name, span<const uint8_t> value,
                        const Name& nodePrefix, time::milliseconds freshnessPeriod,
                        std::vector<Block> mappingBlocks)
{
  std::lock_guard<std::mutex> orderLock(m_segmentedPublishMutex);
  AsyncPublication publication;
  publication.kind = AsyncPublication::Kind::Bytes;
  publication.name = name;
  publication.nodePrefix = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  publication.freshnessPeriod = freshnessPeriod;
  publication.value.assign(value.begin(), value.end());
  publication.mappingBlocks = std::move(mappingBlocks);
  return prepareAndStageAsyncPublication(std::move(publication));
}


SeqNo
SVSPubSub::publish(const Name& name,
                   const Name& nodePrefix, time::milliseconds freshnessPeriod,
                   std::vector<Block> mappingBlocks)
{
  // Segment the data if larger than MAX_DATA_SIZE
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo = reserveSeqNo(nid);
  BootstrapTime bootstrapTime = m_svsync.getCore().getBootstrapTime();

  // Insert mapping and manually update the sequence number
  insertMapping(nid, bootstrapTime, seqNo, name, mappingBlocks);
  m_svsync.getCore().updateSeqNo(seqNo, nid);

  return seqNo;
}

SeqNo
SVSPubSub::publishAsync(const Name& name,
                        const Name& nodePrefix, time::milliseconds freshnessPeriod,
                        std::vector<Block> mappingBlocks)
{
  std::lock_guard<std::mutex> orderLock(m_segmentedPublishMutex);

  AsyncPublication publication;
  publication.kind = AsyncPublication::Kind::NameOnly;
  publication.name = name;
  publication.nodePrefix = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  publication.freshnessPeriod = freshnessPeriod;
  publication.mappingBlocks = std::move(mappingBlocks);
  return prepareAndStageAsyncPublication(std::move(publication));
}

SeqNo
SVSPubSub::publishPacket(const Data& data, const Name& nodePrefix,
                         std::vector<Block> mappingBlocks)
{
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo = reserveSeqNo(nid);
  BootstrapTime bootstrapTime = m_svsync.getCore().getBootstrapTime();
  m_svsync.insertDataAtSeq(data.wireEncode(), data.getFreshnessPeriod(),
                           nid, seqNo, ndn::tlv::Data);
  insertMapping(nid, bootstrapTime, seqNo, data.getName(), mappingBlocks);
  m_svsync.getCore().updateSeqNo(seqNo, nid);
  return seqNo;
}

SeqNo
SVSPubSub::publishPacketAsync(const Data& data, const Name& nodePrefix,
                              std::vector<Block> mappingBlocks)
{
  std::lock_guard<std::mutex> orderLock(m_segmentedPublishMutex);

  AsyncPublication publication;
  publication.kind = AsyncPublication::Kind::Packet;
  publication.name = data.getName();
  publication.nodePrefix = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  publication.freshnessPeriod = data.getFreshnessPeriod();
  publication.packet = data;
  publication.mappingBlocks = std::move(mappingBlocks);
  return prepareAndStageAsyncPublication(std::move(publication));
}

SeqNo
SVSPubSub::reserveSeqNo(const NodeID& nid)
{
  std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
  SeqNo& reserved = m_reservedSeqNo[nid];
  reserved = std::max(reserved, m_svsync.getCore().getSeqNo(nid));
  SeqNo seqNo = ++reserved;
  if (m_nextAsyncCommitSeq.find(nid) == m_nextAsyncCommitSeq.end()) {
    m_nextAsyncCommitSeq[nid] = seqNo;
  }
  return seqNo;
}

SeqNo
SVSPubSub::prepareAndStageAsyncPublication(AsyncPublication publication)
{
  const auto nid = publication.nodePrefix;
  std::unique_lock<std::mutex> reservationLock(m_asyncPublishMutex);
  SeqNo& reserved = m_reservedSeqNo[nid];
  reserved = std::max(reserved, m_svsync.getCore().getSeqNo(nid));
  publication.seqNo = reserved + 1;
  publication.bootstrapTime = m_svsync.getCore().getBootstrapTime();

  PreparedPublication prepared;
  switch (publication.kind) {
    case AsyncPublication::Kind::Bytes:
      prepared = prepareReservedBytes(publication);
      break;
    case AsyncPublication::Kind::NameOnly:
      prepared = prepareReservedNameOnly(publication);
      break;
    case AsyncPublication::Kind::Packet:
      prepared = prepareReservedPacket(publication);
      break;
  }
  if (!prepared.outerPackets.empty()) {
    m_svsync.insertPreparedDataBatch(prepared.outerPackets);
    prepared.stored = true;
  }

  reserved = publication.seqNo;
  if (m_nextAsyncCommitSeq.find(nid) == m_nextAsyncCommitSeq.end()) {
    m_nextAsyncCommitSeq[nid] = publication.seqNo;
  }
  m_stagedPublicationPackets[nid][publication.seqNo] = prepared.outerPackets;
  reservationLock.unlock();

  auto alive = m_asyncPublishAlive;
  boost::asio::post(m_face.getIoContext(),
                    [this, alive, prepared = std::move(prepared)] () mutable {
                      if (!alive || !alive->load(std::memory_order_relaxed)) {
                        return;
                      }
                      try {
                        onPreparedPublication(std::move(prepared));
                      }
                      catch (const std::exception& e) {
                        NDN_LOG_ERROR("event=async_publish_callback_failed error=" << e.what());
                      }
                    });
  return publication.seqNo;
}

SVSPubSub::PreparedPublication
SVSPubSub::prepareReservedBytes(const AsyncPublication& publication)
{
  PreparedPublication prepared;
  prepared.seqNo = publication.seqNo;
  prepared.bootstrapTime = publication.bootstrapTime;
  prepared.nodePrefix = publication.nodePrefix;
  prepared.mappingName = publication.name;
  prepared.freshnessPeriod = publication.freshnessPeriod;
  prepared.mappingBlocks = publication.mappingBlocks;

  ndn::Data data(publication.name);
  data.setContent(make_span(publication.value.data(), publication.value.size()));
  data.setFreshnessPeriod(publication.freshnessPeriod);
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
    m_securityOptions.dataSigner->sign(data);
  }
  const auto innerWireSize = data.wireEncode().size();
  if (innerWireSize <= m_maxPiggyDataSize) {
    prepared.piggyPacket = data;
  }
  else {
    NDN_LOG_TRACE("event=piggyback_skip reason=data_too_large bytes=" << innerWireSize
                  << " limit=" << m_maxPiggyDataSize
                  << " data=" << data.getName());
  }

  Data outer(m_svsync.getDataName(publication.nodePrefix, publication.bootstrapTime,
                                  publication.seqNo));
  outer.setContent(data.wireEncode());
  outer.setFreshnessPeriod(publication.freshnessPeriod);
  outer.setContentType(ndn::tlv::Data);
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
    m_securityOptions.dataSigner->sign(outer);
  }

  if (isFinalPacketSizeAllowed(outer.wireEncode().size())) {
    prepared.putFirstPacketToFace = true;
    prepared.outerPackets.push_back(std::move(outer));
    return prepared;
  }

  prepared.piggyPacket.reset();
  prepared.putFirstPacketToFace = false;
  prepared.outerPackets = prepareSegmentedPackets(publication);
  return prepared;
}

Data
SVSPubSub::prepareOuterSegment(const AsyncPublication& publication, size_t segmentNo,
                               const Name::Component& finalBlock, size_t offset,
                               size_t contentSize)
{
  auto innerName = Name(publication.name).appendVersion(0).appendSegment(segmentNo);
  Data inner(innerName);
  inner.setFreshnessPeriod(publication.freshnessPeriod);
  inner.setContent(make_span(publication.value.data() + offset, contentSize));
  inner.setFinalBlock(finalBlock);
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
    m_securityOptions.dataSigner->sign(inner);
  }

  Data outer(m_svsync.getDataName(publication.nodePrefix, publication.bootstrapTime,
                                  publication.seqNo)
               .appendVersion(0).appendSegment(segmentNo));
  outer.setContent(inner.wireEncode());
  outer.setFreshnessPeriod(publication.freshnessPeriod);
  outer.setContentType(ndn::tlv::Data);
  outer.setFinalBlock(finalBlock);
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
    m_securityOptions.dataSigner->sign(outer);
  }
  outer.wireEncode();
  return outer;
}

std::vector<Data>
SVSPubSub::prepareSegmentedPackets(const AsyncPublication& publication)
{
  if (publication.value.empty()) {
    throw std::invalid_argument("cannot segment an empty publication");
  }

  // FinalBlock changes the signed wire size. Rebuild until its value agrees
  // with the number of packets found by actual signed-outer fitting.
  size_t finalGuess = (publication.value.size() - 1) / MAX_DATA_SIZE;
  for (size_t pass = 0; pass < 16; ++pass) {
    auto finalBlock = name::Component::fromSegment(finalGuess);
    std::vector<Data> packets;
    size_t offset = 0;
    while (offset < publication.value.size()) {
      const size_t upper = std::min(MAX_DATA_SIZE, publication.value.size() - offset);
      size_t low = 1;
      size_t high = upper;
      size_t best = 0;
      std::optional<Data> bestPacket;
      const size_t segmentNo = packets.size();

      while (low <= high) {
        const size_t candidate = low + (high - low) / 2;
        auto packet = prepareOuterSegment(publication, segmentNo, finalBlock,
                                          offset, candidate);
        if (isFinalPacketSizeAllowed(packet.wireEncode().size())) {
          best = candidate;
          bestPacket = std::move(packet);
          low = candidate + 1;
        }
        else {
          high = candidate - 1;
        }
      }

      if (best == 0 || !bestPacket) {
        throw std::length_error("signed SVS segment cannot fit MAX_NDN_PACKET_SIZE");
      }
      packets.push_back(std::move(*bestPacket));
      offset += best;
    }

    const size_t actualFinal = packets.size() - 1;
    if (actualFinal == finalGuess) {
      for (const auto& packet : packets) {
        if (!isFinalPacketSizeAllowed(packet.wireEncode().size())) {
          throw std::length_error("final signed SVS segment exceeds packet limit");
        }
      }
      return packets;
    }
    finalGuess = actualFinal;
  }
  throw std::runtime_error("segmented FinalBlock fitting did not converge");
}

SVSPubSub::PreparedPublication
SVSPubSub::prepareReservedNameOnly(const AsyncPublication& publication)
{
  PreparedPublication prepared;
  prepared.seqNo = publication.seqNo;
  prepared.bootstrapTime = publication.bootstrapTime;
  prepared.nodePrefix = publication.nodePrefix;
  prepared.mappingName = publication.name;
  prepared.freshnessPeriod = publication.freshnessPeriod;
  prepared.mappingBlocks = publication.mappingBlocks;
  return prepared;
}

SVSPubSub::PreparedPublication
SVSPubSub::prepareReservedPacket(const AsyncPublication& publication)
{
  PreparedPublication prepared;
  prepared.seqNo = publication.seqNo;
  prepared.bootstrapTime = publication.bootstrapTime;
  prepared.nodePrefix = publication.nodePrefix;
  prepared.mappingName = publication.packet.getName();
  prepared.freshnessPeriod = publication.packet.getFreshnessPeriod();
  prepared.mappingBlocks = publication.mappingBlocks;
  prepared.putFirstPacketToFace = true;

  Data outer(m_svsync.getDataName(publication.nodePrefix, publication.bootstrapTime,
                                  publication.seqNo));
  outer.setContent(publication.packet.wireEncode());
  outer.setFreshnessPeriod(publication.packet.getFreshnessPeriod());
  outer.setContentType(ndn::tlv::Data);
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
    m_securityOptions.dataSigner->sign(outer);
  }
  outer.wireEncode();
  prepared.outerPackets.push_back(std::move(outer));
  return prepared;
}

void
SVSPubSub::onPreparedPublication(PreparedPublication publication)
{
  const auto nodePrefix = publication.nodePrefix;
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
    auto stagedNode = m_stagedPublicationPackets.find(nodePrefix);
    if (stagedNode != m_stagedPublicationPackets.end()) {
      stagedNode->second.erase(publication.seqNo);
      if (stagedNode->second.empty()) {
        m_stagedPublicationPackets.erase(stagedNode);
      }
    }
    m_preparedPublications[nodePrefix][publication.seqNo] = std::move(publication);
  }
  commitReadyPreparedPublications(nodePrefix);
}

void
SVSPubSub::commitReadyPreparedPublications(const NodeID& nid)
{
  while (true) {
    PreparedPublication publication;
    {
      std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
      auto nextIt = m_nextAsyncCommitSeq.find(nid);
      if (nextIt == m_nextAsyncCommitSeq.end()) {
        break;
      }
      auto nodeIt = m_preparedPublications.find(nid);
      if (nodeIt == m_preparedPublications.end()) {
        break;
      }
      auto pubIt = nodeIt->second.find(nextIt->second);
      if (pubIt == nodeIt->second.end()) {
        break;
      }
      if (pubIt->second.retryScheduled) {
        break;
      }
      publication = std::move(pubIt->second);
      nodeIt->second.erase(pubIt);
      if (nodeIt->second.empty()) {
        m_preparedPublications.erase(nodeIt);
      }
    }
    auto requeueFailedPublication = [&] {
      const auto failedSeq = publication.seqNo;
      ++publication.commitAttempts;
      publication.retryScheduled = true;
      {
        std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
        m_preparedPublications[nid][failedSeq] = std::move(publication);
      }
      schedulePreparedPublicationRetry(nid, failedSeq);
    };
    try {
      if (m_preparedPublicationCommitHook) {
        m_preparedPublicationCommitHook(publication.seqNo);
      }
      commitPreparedPublication(publication);
      m_svsync.getCore().updateSeqNo(publication.seqNo, nid);
    }
    catch (const std::exception& e) {
      NDN_LOG_ERROR("event=async_publish_commit_failed node=" << publication.nodePrefix
                    << " seq=" << publication.seqNo << " error=" << e.what());
      requeueFailedPublication();
      break;
    }
    catch (...) {
      NDN_LOG_ERROR("event=async_publish_commit_failed node=" << publication.nodePrefix
                    << " seq=" << publication.seqNo << " error=unknown");
      requeueFailedPublication();
      break;
    }
    {
      std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
      auto nextIt = m_nextAsyncCommitSeq.find(nid);
      if (nextIt != m_nextAsyncCommitSeq.end() && nextIt->second == publication.seqNo) {
        ++nextIt->second;
      }
    }
  }
}

void
SVSPubSub::schedulePreparedPublicationRetry(const NodeID& nid, SeqNo seqNo)
{
  size_t attempts = 1;
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
    auto nodeIt = m_preparedPublications.find(nid);
    if (nodeIt == m_preparedPublications.end()) {
      return;
    }
    auto pubIt = nodeIt->second.find(seqNo);
    if (pubIt == nodeIt->second.end()) {
      return;
    }
    attempts = pubIt->second.commitAttempts;
  }
  const auto multiplier = int64_t{1} << std::min<size_t>(attempts - 1, 10);
  const auto delay = time::milliseconds(std::max<int64_t>(1, std::min(
    m_opts.asyncCommitRetryMax.count(),
    m_opts.asyncCommitRetryInitial.count() * multiplier)));
  auto alive = m_asyncPublishAlive;
  m_scheduler.schedule(delay, [this, alive, nid, seqNo] {
    if (!alive || !alive->load(std::memory_order_relaxed)) {
      return;
    }
    {
      std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
      auto nodeIt = m_preparedPublications.find(nid);
      if (nodeIt == m_preparedPublications.end()) {
        return;
      }
      auto pubIt = nodeIt->second.find(seqNo);
      if (pubIt == nodeIt->second.end()) {
        return;
      }
      pubIt->second.retryScheduled = false;
    }
    commitReadyPreparedPublications(nid);
  });
}

void
SVSPubSub::commitPreparedPublication(PreparedPublication& publication)
{
  if (!publication.ok) {
    throw std::runtime_error("publication preparation failed");
  }

  if (!publication.stored) {
    m_svsync.insertPreparedDataBatch(publication.outerPackets);
    publication.stored = !publication.outerPackets.empty();
  }
  try {
    insertMapping(publication.nodePrefix, publication.bootstrapTime, publication.seqNo,
                  publication.mappingName, publication.mappingBlocks);

    if (publication.piggyPacket) {
      std::lock_guard<std::mutex> lock(m_extraDataMutex);
      m_piggyDataQueue.push_back({*publication.piggyPacket, 0});
    }
  }
  catch (...) {
    if (publication.stored && !m_svsync.removePreparedDataBatch(publication.outerPackets)) {
      throw std::runtime_error("publication rollback failed after commit error");
    }
    publication.stored = false;
    throw;
  }

  if (publication.putFirstPacketToFace && !publication.outerPackets.empty()) {
    try {
      m_svsync.putPreparedData(publication.outerPackets.front());
    }
    catch (const std::exception& e) {
      NDN_LOG_WARN("event=async_publish_active_put_failed node=" << publication.nodePrefix
                   << " seq=" << publication.seqNo << " error=" << e.what());
    }
    catch (...) {
      NDN_LOG_WARN("event=async_publish_active_put_failed node=" << publication.nodePrefix
                   << " seq=" << publication.seqNo << " error=unknown");
    }
  }
}

void
SVSPubSub::insertMapping(const NodeID& nid, BootstrapTime bootstrapTime, SeqNo seqNo,
                         const Name& name, std::vector<Block> additional)
{
  // additional is a copy deliberately
  // this way we can add well-known mappings to the list

  // add timestamp block
  if (m_opts.useTimestamp) {
    auto timestamp = Name::Component::fromTimestamp(time::system_clock::now());
    additional.push_back(timestamp);
  }

  // create mapping entry
  MappingEntryPair entry = { name, additional };

  // notify subscribers in next sync interest
  {
    std::lock_guard<std::mutex> lock(m_extraDataMutex);
    if (m_notificationMappingList.nodeId == EMPTY_NAME || m_notificationMappingList.nodeId == nid) {
      m_notificationMappingList.nodeId = nid;
      m_notificationMappingList.pairs.push_back({ bootstrapTime, seqNo, entry });
    }
    m_piggyMappingQueue.push_back({nid, {bootstrapTime, seqNo, entry}, 0, 0});
  }

  // send mapping to provider
  m_mappingProvider.insertMapping(nid, bootstrapTime, seqNo, entry);
}

uint32_t
SVSPubSub::subscribe(const Name& prefix, const SubscriptionCallback& callback, bool packets)
{
  uint32_t handle = ++m_subscriptionCount;
  Subscription sub = { handle, prefix, callback, packets, false };
  m_prefixSubscriptions.push_back(sub);
  return handle;
}

uint32_t
SVSPubSub::subscribeWithRegex(const Regex &regex, const SubscriptionCallback &callback,bool autofetch, bool packets)
{
  uint32_t handle = ++m_subscriptionCount;
  Subscription sub = { handle, ndn::Name(), callback, packets, false, autofetch, std::make_shared<Regex>(regex)};
  m_regexSubscriptions.push_back(sub);
  return handle;
}

uint32_t
SVSPubSub::subscribeToProducer(const Name& nodePrefix, const SubscriptionCallback& callback,
                               bool prefetch, bool packets)
{
  uint32_t handle = ++m_subscriptionCount;
  Subscription sub = { handle, nodePrefix, callback, packets, prefetch };
  m_producerSubscriptions.push_back(sub);
  return handle;
}

void
SVSPubSub::unsubscribe(uint32_t handle)
{
  auto unsub = [handle](std::vector<Subscription>& subs) {
    for (auto it = subs.begin(); it != subs.end(); ++it) {
      if (it->id == handle) {
        subs.erase(it);
        return;
      }
    }
  };

  unsub(m_producerSubscriptions);
  unsub(m_prefixSubscriptions);
  unsub(m_regexSubscriptions);
}

void
SVSPubSub::updateCallbackInternal(const std::vector<MissingDataInfo>& info)
{
  for (const auto& stream : info) {
    Name streamName(stream.nodeId);

    // Producer subscriptions
    for (const auto& sub : m_producerSubscriptions) {
      if (sub.prefix.isPrefixOf(streamName)) {
        // Add to fetching queue
        for (SeqNo i = stream.low; i <= stream.high; i++)
          addPublicationFetch(PublicationKey(stream.nodeId, stream.bootstrapTime, i), sub);

        // Prefetch next available data
        if (sub.prefetch)
          m_svsync.fetchData(stream.nodeId, stream.bootstrapTime,
                             stream.high + 1, [](auto&&...) {}); // do nothing with prefetch
      }
    }

    // Fetch all mappings if we have prefix subscription(s) or regex subscription(s)
    if (!m_prefixSubscriptions.empty() || !m_regexSubscriptions.empty()) {
      MissingDataInfo remainingInfo = stream;

      // Attemt to find what we already know about mapping
      // This typically refers to the Sync Interest mapping optimization,
      // where the Sync Interest contains the notification mapping list
      for (SeqNo i = remainingInfo.low; i <= remainingInfo.high; i++) {
        try {
          // throws if mapping not found
          this->processMapping(stream.nodeId, stream.bootstrapTime, i);
          remainingInfo.low++;
        } catch (const std::exception&) {
          break;
        }
      }

      // Find from network what we don't yet know
      while (remainingInfo.high >= remainingInfo.low) {
        // Fetch a max of 10 entries per request
        // This is to ensure the mapping response does not overflow
        // TODO: implement a better solution to this issue
        MissingDataInfo truncatedRemainingInfo = remainingInfo;
        if (truncatedRemainingInfo.high - truncatedRemainingInfo.low > 10) {
          truncatedRemainingInfo.high = truncatedRemainingInfo.low + 10;
        }

        scheduleMappingFetch(truncatedRemainingInfo, streamName);

        remainingInfo.low += 11;
      }
    }
  }

  fetchAll();
  m_onUpdate(info);
}

void
SVSPubSub::addPublicationFetch(const PublicationKey& publication, const Subscription& sub)
{
  m_fetchMap[publication].push_back(sub);

  auto& state = m_publicationFetchStates[publication];
  if (state.firstQueued == SteadyClock::time_point{}) {
    const auto now = SteadyClock::now();
    const auto deadline = m_opts.maxPubAge > 0_ms ? m_opts.maxPubAge : 30_s;
    const ProducerSessionKey session(std::get<0>(publication), std::get<1>(publication));
    auto estimate = m_publicationLifetimeEstimates.find(session);

    state.status = PublicationFetchStatus::Queued;
    state.firstQueued = now;
    state.deadline = now + toStdDuration(deadline);
    state.nextAttempt = now;
    if (estimate != m_publicationLifetimeEstimates.end() && estimate->second.lifetime > 0_ms) {
      state.currentLifetime = estimate->second.lifetime;
    }
    else {
      state.currentLifetime = m_opts.publicationFetchInterestLifetime;
    }
    state.currentLifetime = clampDuration(state.currentLifetime,
                                          m_opts.publicationFetchMinInterestLifetime,
                                          m_opts.publicationFetchMaxInterestLifetime);
    state.currentBackoff = m_opts.publicationFetchFailureBackoff;
  }
}

bool
SVSPubSub::processMapping(const NodeID& nodeId, BootstrapTime bootstrapTime, SeqNo seqNo)
{
  const PublicationKey publication(nodeId, bootstrapTime, seqNo);
  if (hasPiggyDeliveredPublication(publication)) {
    return false;
  }

  // this will throw if mapping not found
  auto mapping = m_mappingProvider.getMapping(nodeId, bootstrapTime, seqNo);

  // check if timestamp is too old
  if (m_opts.maxPubAge > 0_ms) {
    // look for the additional timestamp block
    // if no timestamp block is present, we just skip this step
    for (const auto& block : mapping.second) {
      Name::Component component(block);
      if (!component.isTimestamp())
        continue;

      const auto pubTime = component.toTimestamp();
      if (time::system_clock::now() - pubTime > m_opts.maxPubAge)
        return false;
    }
  }

  bool queued = false;
  bool deliveredFromPiggy = false;
  auto queueOrDeliver = [this, &queued, &deliveredFromPiggy, &mapping, &publication,
                         &nodeId, seqNo](const Subscription& sub) {
    if (sub.autofetch) {
      std::optional<Data> packet;
      {
        std::lock_guard<std::mutex> lock(m_extraDataMutex);
        auto data = m_piggyDataCache.lower_bound(mapping.first);
        auto exactData = m_piggyDataCache.find(mapping.first);
        if (exactData != m_piggyDataCache.end()) {
          packet = exactData->second;
        }
        else if (data != m_piggyDataCache.end() &&
            mapping.first.isPrefixOf(data->first)) {
          packet = data->second;
        }
      }
      if (packet) {
        SubscriptionData subData = {
          mapping.first,
          packet->getContent().value_bytes(),
          nodeId,
          seqNo,
          packet
        };
        sub.callback(subData);
        deliveredFromPiggy = true;
      }
      else {
        addPublicationFetch(publication, sub);
        queued = true;
      }
    }
    else {
      SubscriptionData subData = {
        mapping.first,
        ndn::span<const uint8_t>{},
        nodeId,
        seqNo,
        std::nullopt
      };
      sub.callback(subData);
    }
  };

  // check if known mapping matches subscription
  for (const auto& sub : m_prefixSubscriptions) {
    if (sub.prefix.isPrefixOf(mapping.first)) {
      queueOrDeliver(sub);
    }
  }
  for (const auto& sub : m_regexSubscriptions) {
    if (sub.regex->match(mapping.first)) {
      queueOrDeliver(sub);
    }
  }

  if (deliveredFromPiggy) {
    rememberPiggyDeliveredPublication(publication);
  }

  return queued;
}

void
SVSPubSub::onFetchedNameMappings(const MissingDataInfo& requested,
                                 const NodeID& streamName,
                                 const MappingList& list)
{
  if (list.pairs.empty())
    return;

  const SeqNo requestedHigh = std::max(requested.high, requested.low);
  std::set<SeqNo> returnedSeqs;
  bool queued = false;
  for (const auto& entry : list.pairs) {
    if (entry.bootstrapTime == requested.bootstrapTime &&
        entry.seqNo >= requested.low &&
        entry.seqNo <= requestedHigh) {
      returnedSeqs.insert(entry.seqNo);
    }
    queued |= processMapping(streamName, entry.bootstrapTime, entry.seqNo);
  }

  if (queued)
    fetchAll();

  std::optional<SeqNo> missingLow;
  auto fetchMissingRange = [this, &requested, &streamName](SeqNo low, SeqNo high) {
    MissingDataInfo missing = requested;
    missing.low = low;
    missing.high = high;
    scheduleMappingFetch(missing, streamName);
  };

  for (SeqNo seq = requested.low; seq <= requestedHigh; ++seq) {
    if (returnedSeqs.count(seq) == 0) {
      if (!missingLow)
        missingLow = seq;
      continue;
    }

    if (missingLow) {
      fetchMissingRange(*missingLow, seq - 1);
      missingLow.reset();
    }
  }
  if (missingLow)
    fetchMissingRange(*missingLow, requestedHigh);
}

bool
SVSPubSub::scheduleMappingFetch(const MissingDataInfo& requested,
                                const NodeID& streamName)
{
  MissingDataInfo query = requested;
  query.high = std::max(query.high, query.low);
  const MappingFetchKey key(query.nodeId, query.bootstrapTime, query.low, query.high);
  const auto now = std::chrono::steady_clock::now();

  auto inFlight = m_mappingFetchInFlight.find(key);
  if (inFlight != m_mappingFetchInFlight.end()) {
    NDN_LOG_TRACE("event=mapping_fetch_suppress reason=in_flight node=" << query.nodeId
                  << " bootstrap=" << query.bootstrapTime
                  << " low=" << query.low
                  << " high=" << query.high);
    return false;
  }

  auto suppress = m_mappingFetchSuppressUntil.find(key);
  if (suppress != m_mappingFetchSuppressUntil.end() && suppress->second > now) {
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      suppress->second - now);
    NDN_LOG_TRACE("event=mapping_fetch_suppress reason=backoff node=" << query.nodeId
                  << " bootstrap=" << query.bootstrapTime
                  << " low=" << query.low
                  << " high=" << query.high
                  << " remaining_ms=" << remaining.count());
    return false;
  }

  if (suppress != m_mappingFetchSuppressUntil.end())
    m_mappingFetchSuppressUntil.erase(suppress);
  m_mappingFetchInFlight[key] = true;

  m_mappingProvider.fetchNameMapping(
    query,
    [this, query, streamName, key](const MappingList& list) {
      this->markMappingFetchComplete(key);
      this->onFetchedNameMappings(query, streamName, list);
    },
    [this, key](const Interest&) {
      this->markMappingFetchFailed(key);
    },
    m_opts.mappingFetchRetries);
  return true;
}

void
SVSPubSub::markMappingFetchComplete(const MappingFetchKey& key)
{
  m_mappingFetchInFlight.erase(key);
  m_mappingFetchSuppressUntil.erase(key);
}

void
SVSPubSub::markMappingFetchFailed(const MappingFetchKey& key)
{
  m_mappingFetchInFlight.erase(key);
  if (m_opts.mappingFetchFailureBackoff > 0_ms) {
    m_mappingFetchSuppressUntil[key] = std::chrono::steady_clock::now() +
      std::chrono::milliseconds(m_opts.mappingFetchFailureBackoff.count());
  }
}

void
SVSPubSub::markPublicationFetchFailed(const PublicationKey& key)
{
  auto fetchIt = m_fetchMap.find(key);
  auto stateIt = m_publicationFetchStates.find(key);
  if (fetchIt == m_fetchMap.end() || stateIt == m_publicationFetchStates.end()) {
    return;
  }

  auto& state = stateIt->second;
  const auto now = SteadyClock::now();
  const bool retryBudgetExhausted =
    m_opts.publicationFetchRetries >= 0 &&
    state.attempts > static_cast<size_t>(m_opts.publicationFetchRetries);
  if (retryBudgetExhausted || now >= state.deadline) {
    state.status = PublicationFetchStatus::Expired;
    NDN_LOG_TRACE("event=publication_fetch_expired node=" << std::get<0>(key)
                  << " bootstrap=" << std::get<1>(key)
                  << " seq=" << std::get<2>(key)
                  << " attempts=" << state.attempts);
    cleanUpFetch(key);
    return;
  }

  rememberRepairRequest(key);
  state.status = PublicationFetchStatus::Backoff;
  if (state.currentBackoff <= 0_ms) {
    state.currentBackoff = m_opts.publicationFetchFailureBackoff;
  }
  state.nextAttempt = now + toStdDuration(state.currentBackoff);
  state.currentLifetime =
    clampDuration(state.currentLifetime * 2,
                  m_opts.publicationFetchMinInterestLifetime,
                  m_opts.publicationFetchMaxInterestLifetime);

  const ProducerSessionKey session(std::get<0>(key), std::get<1>(key));
  m_publicationLifetimeEstimates[session].lifetime = state.currentLifetime;

  NDN_LOG_TRACE("event=publication_fetch_retry_scheduled node=" << std::get<0>(key)
                << " bootstrap=" << std::get<1>(key)
                << " seq=" << std::get<2>(key)
                << " attempts=" << state.attempts
                << " backoff_ms=" << state.currentBackoff.count()
                << " next_lifetime_ms=" << state.currentLifetime.count());

  const auto nextBackoff = clampDuration(state.currentBackoff * 2,
                                         m_opts.publicationFetchFailureBackoff,
                                         m_opts.publicationFetchMaxBackoff);
  state.currentBackoff = nextBackoff;

  m_scheduler.schedule(toNdnDuration(state.nextAttempt - now),
                       [this] {
                         fetchAll();
                       });
}

void
SVSPubSub::observePublicationFetchSuccess(const PublicationKey& key)
{
  auto stateIt = m_publicationFetchStates.find(key);
  if (stateIt == m_publicationFetchStates.end()) {
    return;
  }

  auto& state = stateIt->second;
  const auto now = SteadyClock::now();
  if (state.attemptStarted != SteadyClock::time_point{}) {
    auto rtt = toNdnDuration(now - state.attemptStarted);
    if (rtt <= 0_ms) {
      rtt = 1_ms;
    }
    const auto target = clampDuration(rtt * 2,
                                      m_opts.publicationFetchMinInterestLifetime,
                                      m_opts.publicationFetchMaxInterestLifetime);
    const ProducerSessionKey session(std::get<0>(key), std::get<1>(key));
    auto& estimate = m_publicationLifetimeEstimates[session];
    if (estimate.lifetime <= 0_ms) {
      estimate.lifetime = target;
    }
    else {
      estimate.lifetime = clampDuration((estimate.lifetime + target) / 2,
                                        m_opts.publicationFetchMinInterestLifetime,
                                        m_opts.publicationFetchMaxInterestLifetime);
    }
    state.currentLifetime = estimate.lifetime;
    NDN_LOG_TRACE("event=publication_fetch_success node=" << std::get<0>(key)
                  << " bootstrap=" << std::get<1>(key)
                  << " seq=" << std::get<2>(key)
                  << " attempts=" << state.attempts
                  << " rtt_ms=" << rtt.count()
                  << " next_lifetime_ms=" << estimate.lifetime.count());
  }
  state.status = PublicationFetchStatus::Delivered;
}

void
SVSPubSub::rememberRepairRequest(const PublicationKey& key)
{
  MissingDataInfo info;
  info.nodeId = std::get<0>(key);
  info.bootstrapTime = std::get<1>(key);
  info.low = std::get<2>(key);
  info.high = std::get<2>(key);

  std::lock_guard<std::mutex> lock(m_extraDataMutex);
  for (const auto& entry : m_repairRequestQueue) {
    if (entry.info.nodeId == info.nodeId &&
        entry.info.bootstrapTime == info.bootstrapTime &&
        entry.info.low == info.low &&
        entry.info.high == info.high) {
      return;
    }
  }
  m_repairRequestQueue.push_back({info, 0, 0});
}

void
SVSPubSub::enqueueRepairPublication(const PublicationKey& key)
{
  const auto& [nodeId, bootstrapTime, seqNo] = key;
  try {
    auto mapping = m_mappingProvider.getMapping(nodeId, bootstrapTime, seqNo);
    std::lock_guard<std::mutex> lock(m_extraDataMutex);
    m_piggyMappingQueue.push_back({nodeId, {bootstrapTime, seqNo, mapping}, 0, 0});
  }
  catch (const std::exception&) {
    return;
  }

  try {
    Interest interest(m_svsync.getDataName(nodeId, bootstrapTime, seqNo));
    interest.setCanBePrefix(true);
    auto outer = m_svsync.getDataStore().find(interest);
    if (!outer || outer->getContentType() != ndn::tlv::Data) {
      return;
    }
    Data inner(outer->getContent().blockFromValue());
    if (inner.wireEncode().size() > m_maxPiggyDataSize) {
      return;
    }
    std::lock_guard<std::mutex> lock(m_extraDataMutex);
    m_piggyDataQueue.push_back({inner, 0, 0});
  }
  catch (const std::exception&) {
  }
}

void
SVSPubSub::fetchAll()
{
  const auto now = SteadyClock::now();
  size_t inFlight = 0;
  std::vector<PublicationKey> ready;
  ready.reserve(m_fetchMap.size());

  for (const auto& pair : m_fetchMap) {
    const auto& key = pair.first;
    auto& state = m_publicationFetchStates[key];
    if (state.firstQueued == SteadyClock::time_point{}) {
      state.status = PublicationFetchStatus::Queued;
      state.firstQueued = now;
      state.deadline = now + toStdDuration(m_opts.maxPubAge > 0_ms ? m_opts.maxPubAge : 30_s);
      state.nextAttempt = now;
      state.currentLifetime = clampDuration(m_opts.publicationFetchInterestLifetime,
                                            m_opts.publicationFetchMinInterestLifetime,
                                            m_opts.publicationFetchMaxInterestLifetime);
      state.currentBackoff = m_opts.publicationFetchFailureBackoff;
    }

    if (state.status == PublicationFetchStatus::Fetching) {
      ++inFlight;
      continue;
    }
    if (state.status == PublicationFetchStatus::Delivered ||
        state.status == PublicationFetchStatus::Expired) {
      continue;
    }
    if (now >= state.deadline) {
      state.status = PublicationFetchStatus::Expired;
      continue;
    }
    if (state.nextAttempt <= now) {
      ready.push_back(key);
    }
  }

  for (auto it = m_publicationFetchStates.begin(); it != m_publicationFetchStates.end();) {
    if (it->second.status == PublicationFetchStatus::Expired &&
        m_fetchMap.find(it->first) != m_fetchMap.end()) {
      NDN_LOG_TRACE("event=publication_fetch_expired node=" << std::get<0>(it->first)
                    << " bootstrap=" << std::get<1>(it->first)
                    << " seq=" << std::get<2>(it->first)
                    << " attempts=" << it->second.attempts);
      m_fetchMap.erase(it->first);
      it = m_publicationFetchStates.erase(it);
      continue;
    }
    ++it;
  }

  std::sort(ready.begin(), ready.end(), [this](const PublicationKey& lhs, const PublicationKey& rhs) {
    const auto& lhsState = m_publicationFetchStates.at(lhs);
    const auto& rhsState = m_publicationFetchStates.at(rhs);
    if (lhsState.attempts != rhsState.attempts) {
      return lhsState.attempts < rhsState.attempts;
    }
    if (std::get<1>(lhs) != std::get<1>(rhs)) {
      return std::get<1>(lhs) > std::get<1>(rhs);
    }
    return std::get<2>(lhs) > std::get<2>(rhs);
  });

  const size_t window = std::max<size_t>(1, m_opts.publicationFetchWindow);
  for (const auto& key : ready) {
    if (inFlight >= window) {
      break;
    }
    if (m_fetchMap.find(key) == m_fetchMap.end())
      continue;
    auto stateIt = m_publicationFetchStates.find(key);
    if (stateIt == m_publicationFetchStates.end())
      continue;
    auto& state = stateIt->second;
    if (state.status == PublicationFetchStatus::Fetching || state.nextAttempt > now)
      continue;

    // Fetch first data packet
    const auto& [nodeId, bootstrapTime, seqNo] = key;
    try {
      const auto mapping = m_mappingProvider.getMapping(nodeId, bootstrapTime, seqNo);
      std::optional<Data> packet;
      {
        std::lock_guard<std::mutex> lock(m_extraDataMutex);
        auto data = m_piggyDataCache.lower_bound(mapping.first);
        auto exactData = m_piggyDataCache.find(mapping.first);
        if (exactData != m_piggyDataCache.end()) {
          packet = exactData->second;
        }
        else if (data != m_piggyDataCache.end() &&
            mapping.first.isPrefixOf(data->first)) {
          packet = data->second;
        }
      }
      if (packet) {
        SubscriptionData subData = {
          mapping.first,
          packet->getContent().value_bytes(),
          nodeId,
          seqNo,
          packet,
        };
        for (const auto& sub : m_fetchMap[key]) {
          sub.callback(subData);
        }
        rememberPiggyDeliveredPublication(key);
        NDN_LOG_TRACE("event=piggyback_cache_satisfy data=" << packet->getName()
                      << " node=" << nodeId
                      << " seq=" << seqNo);
        observePublicationFetchSuccess(key);
        cleanUpFetch(key);
        continue;
      }
    }
    catch (const std::exception&) {
    }
    state.status = PublicationFetchStatus::Fetching;
    state.attemptStarted = now;
    state.currentLifetime =
      clampDuration(state.currentLifetime,
                    m_opts.publicationFetchMinInterestLifetime,
                    m_opts.publicationFetchMaxInterestLifetime);
    ++state.attempts;
    ++inFlight;
    m_svsync.setFetchInterestLifetime(state.currentLifetime);
    m_svsync.fetchData(nodeId, bootstrapTime, seqNo,
                       std::bind(&SVSPubSub::onSyncData, this, _1, key),
                       [](auto&&...) {},
	                       [this, key](const Interest&) {
	                         markPublicationFetchFailed(key);
	                       },
	                       m_opts.publicationFetchInnerRetries);
  }
}

std::optional<SVSPubSub::InnerSegmentAssembly>
SVSPubSub::decodeInnerSegments(const std::vector<Block>& blocks)
{
  try {
    if (blocks.empty()) {
      return std::nullopt;
    }

    std::map<size_t, Data> segments;
    std::optional<size_t> expectedFinal;
    std::optional<Name> baseName;
    for (const auto& block : blocks) {
      Data inner(block);
      const auto& name = inner.getName();
      if (name.size() < 2 || !name[-1].isSegment() || !name[-2].isVersion() ||
          !inner.getFinalBlock() || !inner.getFinalBlock()->isSegment()) {
        return std::nullopt;
      }
      const auto segmentNo = name[-1].toSegment();
      const auto finalSegment = inner.getFinalBlock()->toSegment();
      if (segmentNo > finalSegment || inner.getContent().value_size() == 0) {
        return std::nullopt;
      }
      const auto currentBase = name.getPrefix(-2);
      if ((baseName && *baseName != currentBase) ||
          (expectedFinal && *expectedFinal != finalSegment) ||
          !segments.emplace(segmentNo, inner).second) {
        return std::nullopt;
      }
      baseName = currentBase;
      expectedFinal = finalSegment;
    }

    if (!expectedFinal || segments.size() != *expectedFinal + 1) {
      return std::nullopt;
    }

    InnerSegmentAssembly assembled{*baseName, {}};
    for (size_t segmentNo = 0; segmentNo <= *expectedFinal; ++segmentNo) {
      auto it = segments.find(segmentNo);
      if (it == segments.end()) {
        return std::nullopt;
      }
      const auto content = it->second.getContent().value_bytes();
      assembled.payload.insert(assembled.payload.end(), content.begin(), content.end());
    }
    return assembled;
  }
  catch (const std::exception&) {
    return std::nullopt;
  }
}

void
SVSPubSub::onSyncData(const Data& firstData, const PublicationKey& publication)
{
  auto alive = m_asyncPublishAlive;
  const auto& nodeId = std::get<0>(publication);
  const auto seqNo = std::get<2>(publication);

  // Make sure the data is encapsulated
  if (firstData.getContentType() != ndn::tlv::Data) {
    markPublicationFetchFailed(publication);
    return;
  }
  observePublicationFetchSuccess(publication);

  std::shared_ptr<Data> innerData;
  try {
    innerData = std::make_shared<Data>(firstData.getContent().blockFromValue());
  }
  catch (const std::exception&) {
    cleanUpFetch(publication);
    return;
  }

  // Function to return data to subscriptions
  auto returnData = [this, alive, firstData, innerData, publication, nodeId, seqNo]() {
    if (!alive->load(std::memory_order_relaxed)) {
      return;
    }
    auto fetchIt = m_fetchMap.find(publication);
    if (fetchIt == m_fetchMap.end()) {
      return;
    }

    const auto innerContent = innerData->getContent().value_bytes();
    const std::optional<Data> packet = *innerData;
    SubscriptionData subData = {
      innerData->getName(), innerContent, nodeId, seqNo, packet,
    };
    bool hasFinalBlock = innerData->getFinalBlock().has_value();
    bool hasBlobSubcriptions = false;

    for (const auto& sub : fetchIt->second) {
      if (sub.isPacketSubscription || !hasFinalBlock)
        sub.callback(subData);

      hasBlobSubcriptions |= !sub.isPacketSubscription;
    }

    // If there are blob subscriptions and a final block, we need to fetch
    // remaining segments
    if (hasBlobSubcriptions && hasFinalBlock && firstData.getName().size() > 2) {
      // Fetch remaining segments
      auto pubName = firstData.getName().getPrefix(-2);
      Interest interest(pubName); // strip off version and segment number
      ndn::SegmentFetcher::Options opts;
      auto fetcher = ndn::SegmentFetcher::start(m_face, interest, m_nullValidator, opts);

      fetcher->onComplete.connectSingleShot([this, alive, publication](const ndn::ConstBufferPtr& data) {
        if (!alive->load(std::memory_order_relaxed)) {
          return;
        }
        try {
          // Read all TLVs as Data packets till the end of data buffer
          ndn::Block block(6, data);
          block.parse();
          std::vector<Block> innerBlocks(block.elements().begin(), block.elements().end());
          auto assembly = decodeInnerSegments(innerBlocks);
          if (!assembly) {
            cleanUpFetch(publication);
            return;
          }

          struct ValidationState
          {
            Name name;
            std::vector<uint8_t> payload;
            size_t completed = 0;
            size_t failed = 0;
            size_t expected = 0;
            bool terminal = false;
            std::mutex mutex;
          };
          auto state = std::make_shared<ValidationState>();
          state->name = std::move(assembly->name);
          state->payload = std::move(assembly->payload);
          state->expected = innerBlocks.size();

          auto finishOne = [this, alive, publication, state](bool failed) {
            bool finish = false;
            bool deliver = false;
            {
              std::lock_guard<std::mutex> lock(state->mutex);
              if (state->terminal) {
                return;
              }
              ++state->completed;
              state->failed += failed ? 1 : 0;
              if (state->completed == state->expected) {
                state->terminal = true;
                finish = true;
                deliver = state->failed == 0;
              }
            }
            if (!finish || !alive->load(std::memory_order_relaxed)) {
              return;
            }
            if (deliver) {
              auto it = m_fetchMap.find(publication);
              if (it != m_fetchMap.end()) {
                SubscriptionData subData = {
                  state->name, state->payload, std::get<0>(publication),
                  std::get<2>(publication), std::nullopt,
                };
                for (const auto& sub : it->second) {
                  if (!sub.isPacketSubscription) {
                    sub.callback(subData);
                  }
                }
              }
            }
            cleanUpFetch(publication);
          };

          for (const auto& innerBlock : innerBlocks) {
            Data packet(innerBlock);
            if (m_securityOptions.encapsulatedDataValidator) {
              m_securityOptions.encapsulatedDataValidator->validate(
                packet,
                [finishOne](auto&&...) { finishOne(false); },
                [finishOne](auto&&...) { finishOne(true); });
            }
            else {
              finishOne(false);
            }
          }
        } catch (const std::exception&) {
          if (alive->load(std::memory_order_relaxed)) {
            cleanUpFetch(publication);
          }
        }
      });
      fetcher->onError.connectSingleShot([this, alive, publication](uint32_t, const std::string&) {
        if (alive->load(std::memory_order_relaxed)) {
          cleanUpFetch(publication);
        }
      });
    } else {
      cleanUpFetch(publication);
    }
  };

  // Validate encapsulated packet
  if (m_securityOptions.encapsulatedDataValidator) {
    m_securityOptions.encapsulatedDataValidator->validate(
      *innerData,
      [alive, returnData](auto&&...) {
        if (alive->load(std::memory_order_relaxed)) {
          returnData();
        }
      },
      [this, alive, publication](auto&&...) {
        if (alive->load(std::memory_order_relaxed)) {
          cleanUpFetch(publication);
        }
      });
  } else {
    returnData();
  }
}

void
SVSPubSub::cleanUpFetch(const PublicationKey& publication)
{
  m_fetchMap.erase(publication);
  m_publicationFetchStates.erase(publication);
}

bool
SVSPubSub::hasPiggyDeliveredPublication(const PublicationKey& publication)
{
  std::lock_guard<std::mutex> lock(m_extraDataMutex);
  return m_piggyDeliveredPublications.find(publication) != m_piggyDeliveredPublications.end();
}

void
SVSPubSub::rememberPiggyDeliveredPublication(const PublicationKey& publication)
{
  std::lock_guard<std::mutex> lock(m_extraDataMutex);
  if (m_piggyDeliveredPublications.find(publication) == m_piggyDeliveredPublications.end()) {
    m_piggyDeliveredPublicationOrder.push_back(publication);
  }
  m_piggyDeliveredPublications[publication] = true;
  while (m_piggyDeliveredPublications.size() > m_piggyDeliveredPublicationLimit &&
         !m_piggyDeliveredPublicationOrder.empty()) {
    m_piggyDeliveredPublications.erase(m_piggyDeliveredPublicationOrder.front());
    m_piggyDeliveredPublicationOrder.pop_front();
  }
}

bool
SVSPubSub::satisfyPendingFetchFromPiggyData(const Data& data)
{
  std::vector<std::pair<PublicationKey, std::vector<Subscription>>> ready;

  for (const auto& entry : m_fetchMap)
  {
    const auto& publication = entry.first;
    try {
      auto mapping = m_mappingProvider.getMapping(std::get<0>(publication),
                                                  std::get<1>(publication),
                                                  std::get<2>(publication));
      if (mapping.first == data.getName()) {
        ready.push_back(entry);
      }
    }
    catch (const std::exception&) {
    }
  }

  for (const auto& [publication, subscriptions] : ready)
  {
    std::optional<Data> packet(data);
    SubscriptionData subData = {
      data.getName(),
      data.getContent().value_bytes(),
      std::get<0>(publication),
      std::get<2>(publication),
      packet,
    };

    for (const auto& sub : subscriptions) {
      sub.callback(subData);
    }
    rememberPiggyDeliveredPublication(publication);
    cleanUpFetch(publication);
  }

  NDN_LOG_TRACE("event=piggyback_satisfy data=" << data.getName()
                << " matches=" << ready.size());

  return !ready.empty();
}

Block
SVSPubSub::onGetExtraData(const VersionVector&)
{
  const auto totalStart = SteadyClock::now();
  std::lock_guard<std::mutex> lock(m_extraDataMutex);
  const auto lockedAt = SteadyClock::now();

  MappingList includedMappings(m_notificationMappingList.nodeId);
  size_t mappingCount = 0;
  size_t repeatedMappingCount = 0;
  size_t piggyCount = 0;
  size_t repairCount = 0;
  const auto mappingStart = SteadyClock::now();
  if (m_notificationMappingList.nodeId != EMPTY_NAME) {
    for (const auto& entry : m_notificationMappingList.pairs) {
      MappingList candidate = includedMappings;
      candidate.pairs.push_back(entry);
      auto candidateBlock = candidate.encode();
      if (candidateBlock.size() <= m_maxApplicationParametersSize) {
        includedMappings = std::move(candidate);
        ++mappingCount;
      }
      // Overflow mappings are intentionally omitted from this latency-oriented
      // piggyback path; peers can still fetch them from MappingProvider.
    }
  }
  const auto mappingDone = SteadyClock::now();

  const auto initialEncodeStart = SteadyClock::now();
  ndn::Block block = includedMappings.encode();
  block.parse();
  const auto initialEncodeDone = SteadyClock::now();
  size_t size = block.size();
  size_t retainedCount = 0;
  size_t expiredCount = 0;
  size_t retainedMappingCount = 0;
  size_t expiredMappingCount = 0;
  size_t retainedRepairCount = 0;
  size_t expiredRepairCount = 0;
  std::deque<PiggyMappingEntry> retainedMappings;
  const auto repeatedMappingStart = SteadyClock::now();
  for (auto it = m_piggyMappingQueue.rbegin(); it != m_piggyMappingQueue.rend(); ++it) {
    MappingList repairMapping(it->nodeId);
    repairMapping.pairs.push_back(it->mapping);
    auto mappingBlock = repairMapping.encode();
    if (size + mappingBlock.size() > m_maxApplicationParametersSize) {
      ++it->missed;
      if (it->missed < m_opts.piggybackMissLimit) {
        retainedMappings.push_front(*it);
        ++retainedMappingCount;
      }
      else {
        ++expiredMappingCount;
      }
      continue;
    }

    block.push_back(mappingBlock);
    size += mappingBlock.size();
    ++repeatedMappingCount;
    ++it->sent;
    if (it->sent < m_opts.piggybackRepeatCount) {
      retainedMappings.push_front(*it);
      ++retainedMappingCount;
    }
  }
  m_piggyMappingQueue = std::move(retainedMappings);
  const auto repeatedMappingDone = SteadyClock::now();

  std::deque<PiggyDataEntry> retained;
  const auto piggyStart = SteadyClock::now();
  for (auto it = m_piggyDataQueue.rbegin(); it != m_piggyDataQueue.rend(); ++it) {
    auto dataBlock = it->data.wireEncode();
    if (size + dataBlock.size() > m_maxApplicationParametersSize) {
      ++it->missed;
      if (it->missed < m_opts.piggybackMissLimit) {
        retained.push_front(*it);
        ++retainedCount;
      }
      else {
        ++expiredCount;
        NDN_LOG_TRACE("event=piggyback_drop reason=missed_too_many bytes="
                      << dataBlock.size()
                      << " data=" << it->data.getName());
      }
      continue;
    }

    block.push_back(dataBlock);
    size += dataBlock.size();
    ++piggyCount;
    ++it->sent;
    if (it->sent < m_opts.piggybackRepeatCount) {
      retained.push_front(*it);
      ++retainedCount;
    }
  }
  m_piggyDataQueue = std::move(retained);
  const auto piggyDone = SteadyClock::now();

  std::deque<RepairRequestEntry> retainedRepairs;
  const auto repairStart = SteadyClock::now();
  for (auto it = m_repairRequestQueue.rbegin(); it != m_repairRequestQueue.rend(); ++it) {
    auto repairBlock = encodeRepairRequests({it->info});
    if (size + repairBlock.size() > m_maxApplicationParametersSize) {
      ++it->missed;
      if (it->missed < m_opts.piggybackMissLimit) {
        retainedRepairs.push_front(*it);
        ++retainedRepairCount;
      }
      else {
        ++expiredRepairCount;
      }
      continue;
    }

    block.push_back(repairBlock);
    size += repairBlock.size();
    ++repairCount;
    ++it->sent;
    if (it->sent < m_opts.repairRequestRepeatCount) {
      retainedRepairs.push_front(*it);
      ++retainedRepairCount;
    }
  }
  m_repairRequestQueue = std::move(retainedRepairs);
  const auto repairDone = SteadyClock::now();

  const auto finalEncodeStart = SteadyClock::now();
  block.encode();
  const auto finalEncodeDone = SteadyClock::now();

  NDN_LOG_TRACE("event=piggyback_build mappings=" << mappingCount
                << " repeated_mappings=" << repeatedMappingCount
                << " data=" << piggyCount
                << " repairs=" << repairCount
                << " retained=" << retainedCount
                << " expired=" << expiredCount
                << " retained_mappings=" << retainedMappingCount
                << " expired_mappings=" << expiredMappingCount
                << " retained_repairs=" << retainedRepairCount
                << " expired_repairs=" << expiredRepairCount
                << " bytes=" << block.size()
                << " appParamLimit=" << m_maxApplicationParametersSize
                << " piggyDataLimit=" << m_maxPiggyDataSize);
  NDN_LOG_TRACE("event=extra_mapping_build_timing mappings=" << mappingCount
                << " repeated_mappings=" << repeatedMappingCount
                << " data=" << piggyCount
                << " repairs=" << repairCount
                << " bytes=" << block.size()
                << " lock_wait_us=" << elapsedUs(totalStart, lockedAt)
                << " mapping_select_us=" << elapsedUs(mappingStart, mappingDone)
                << " initial_mapping_encode_us=" << elapsedUs(initialEncodeStart, initialEncodeDone)
                << " repeated_mapping_pack_us=" << elapsedUs(repeatedMappingStart, repeatedMappingDone)
                << " piggy_pack_us=" << elapsedUs(piggyStart, piggyDone)
                << " repair_pack_us=" << elapsedUs(repairStart, repairDone)
                << " final_encode_us=" << elapsedUs(finalEncodeStart, finalEncodeDone)
                << " total_us=" << elapsedUs(totalStart, finalEncodeDone));

  m_notificationMappingList = MappingList();

  return block;
}

std::vector<Block>
SVSPubSub::onGetExtraBlocks(const VersionVector& vv)
{
  auto composite = onGetExtraData(vv);
  composite.parse();

  Block mappings(tlv::MappingData);
  std::vector<MissingDataInfo> repairs;
  for (const auto& child : composite.elements()) {
    if (child.type() == tlv::RepairData) {
      auto requests = decodeRepairRequests(child);
      repairs.insert(repairs.end(), requests.begin(), requests.end());
    }
    else {
      mappings.push_back(child);
    }
  }
  mappings.encode();

  std::vector<Block> extensions;
  extensions.push_back(std::move(mappings));
  if (!repairs.empty()) {
    extensions.push_back(encodeRepairRequests(repairs));
  }
  return extensions;
}

void
SVSPubSub::onRecvExtraBlocks(const std::vector<Block>& blocks, const VersionVector& vv)
{
  std::set<uint32_t> knownTypes;
  try {
    if (blocks.size() > SyncProtocolCodec::MAX_EXTENSION_BLOCKS) {
      NDN_THROW(std::invalid_argument("too many SVS extension blocks"));
    }
    for (const auto& block : blocks) {
      if (block.type() != tlv::MappingData && block.type() != tlv::RepairData) {
        continue;
      }
      if (!knownTypes.insert(block.type()).second) {
        NDN_THROW(std::invalid_argument("duplicate known SVS extension"));
      }
      block.parse();
      if (block.type() == tlv::MappingData) {
        static_cast<void>(MappingList(block));
      }
      else {
        static_cast<void>(decodeRepairRequests(block));
      }
      for (const auto& child : block.elements()) {
        if (child.type() == tlv::MappingData) {
          static_cast<void>(MappingList(child));
        }
        else if (child.type() == ndn::tlv::Data) {
          static_cast<void>(Data(child));
        }
        else if (child.type() == tlv::RepairData) {
          static_cast<void>(decodeRepairRequests(child));
        }
      }
    }
  }
  catch (const std::exception& e) {
    NDN_LOG_DEBUG("event=piggyback_recv_collection_rejected_atomic error=" << e.what());
    return;
  }

  for (const auto& block : blocks) {
    onRecvExtraData(block, vv);
  }
}

void
SVSPubSub::onRecvExtraData(const Block& block, const VersionVector&)
{
  const auto totalStart = SteadyClock::now();
  std::vector<PublicationKey> receivedMappings;
  size_t topLevelMappings = 0;
  uint64_t topLevelParseUs = 0;
  // Prepare: validate the complete known extension tree before changing any
  // mapping, repair, fetch, or cache state. Unknown child blocks are ignored.
  try {
    if (block.type() != tlv::MappingData && block.type() != tlv::RepairData) {
      NDN_LOG_TRACE("event=piggyback_recv_unknown_extension type=" << block.type());
      return;
    }
    block.parse();
    if (block.type() == tlv::MappingData) {
      static_cast<void>(MappingList(block));
    }
    else {
      static_cast<void>(decodeRepairRequests(block));
    }
    for (const auto& child : block.elements()) {
      if (child.type() == tlv::MappingData) {
        static_cast<void>(MappingList(child));
      }
      else if (child.type() == ndn::tlv::Data) {
        static_cast<void>(Data(child));
      }
      else if (child.type() == tlv::RepairData) {
        static_cast<void>(decodeRepairRequests(child));
      }
    }
  }
  catch (const std::exception& e) {
    NDN_LOG_DEBUG("event=piggyback_recv_rejected_atomic type=" << block.type()
                  << " error=" << e.what());
    return;
  }

  try {
    NDN_LOG_TRACE("event=piggyback_recv_block type=" << block.type()
                  << " bytes=" << block.size());
    const auto parseStart = SteadyClock::now();
    MappingList list(block);
    for (const auto& entry : list.pairs) {
      m_mappingProvider.insertMapping(list.nodeId, entry.bootstrapTime, entry.seqNo, entry.mapping);
      receivedMappings.emplace_back(list.nodeId, entry.bootstrapTime, entry.seqNo);
    }
    topLevelParseUs = elapsedUs(parseStart, SteadyClock::now());
    topLevelMappings = list.pairs.size();
    NDN_LOG_TRACE("event=piggyback_recv_mapping_list node=" << list.nodeId
                  << " mappings=" << list.pairs.size());
  } catch (const std::exception& e) {
    NDN_LOG_TRACE("event=piggyback_recv_mapping_list_error error=" << e.what());
  }

  if (block.type() == tlv::RepairData) {
    for (const auto& request : decodeRepairRequests(block)) {
      for (SeqNo seq = request.low; seq <= request.high; ++seq) {
        enqueueRepairPublication(PublicationKey(request.nodeId, request.bootstrapTime, seq));
      }
    }
  }

  size_t mappingCount = 0;
  size_t dataCount = 0;
  size_t repairRequestCount = 0;
  uint64_t blockParseUs = 0;
  uint64_t childMappingParseUs = 0;
  uint64_t childDataParseUs = 0;
  uint64_t childRepairParseUs = 0;
  uint64_t childCacheUs = 0;
  try {
    const auto blockParseStart = SteadyClock::now();
    block.parse();
    blockParseUs = elapsedUs(blockParseStart, SteadyClock::now());
    for (const auto& childBlock : block.elements()) {
      NDN_LOG_TRACE("event=piggyback_recv_child type=" << childBlock.type()
                    << " bytes=" << childBlock.size());
      if (childBlock.type() == ndn::svs::tlv::MappingData) {
        const auto childMappingStart = SteadyClock::now();
        MappingList childList(childBlock);
        for (const auto& entry : childList.pairs) {
          m_mappingProvider.insertMapping(childList.nodeId, entry.bootstrapTime,
                                          entry.seqNo, entry.mapping);
          receivedMappings.emplace_back(childList.nodeId, entry.bootstrapTime, entry.seqNo);
        }
        childMappingParseUs += elapsedUs(childMappingStart, SteadyClock::now());
        mappingCount += childList.pairs.size();
      }

      if (childBlock.type() == ndn::tlv::Data) {
        const auto childDataStart = SteadyClock::now();
        ndn::Data data(childBlock);
        satisfyPendingFetchFromPiggyData(data);
        childDataParseUs += elapsedUs(childDataStart, SteadyClock::now());
        try {
          const auto cacheStart = SteadyClock::now();
          std::lock_guard<std::mutex> lock(m_extraDataMutex);
          const auto dataName = data.getName();
          if (m_piggyDataCache.find(dataName) == m_piggyDataCache.end()) {
            m_piggyDataCacheOrder.push_back(dataName);
          }
          m_piggyDataCache[dataName] = data;
          const auto fullName = data.getFullName();
          if (m_piggyDataCache.find(fullName) == m_piggyDataCache.end()) {
            m_piggyDataCacheOrder.push_back(fullName);
          }
          m_piggyDataCache[fullName] = data;
          while (m_piggyDataCache.size() > m_piggyDataCacheLimit &&
                 !m_piggyDataCacheOrder.empty()) {
            m_piggyDataCache.erase(m_piggyDataCacheOrder.front());
            m_piggyDataCacheOrder.pop_front();
          }
          childCacheUs += elapsedUs(cacheStart, SteadyClock::now());
        }
        catch (const std::exception&) {
        }
        ++dataCount;
      }

      if (childBlock.type() == ndn::svs::tlv::RepairData) {
        const auto childRepairStart = SteadyClock::now();
        for (const auto& request : decodeRepairRequests(childBlock)) {
          const SeqNo high = std::max(request.high, request.low);
          for (SeqNo seq = request.low; seq <= high; ++seq) {
            enqueueRepairPublication(PublicationKey(request.nodeId, request.bootstrapTime, seq));
            ++repairRequestCount;
          }
        }
        childRepairParseUs += elapsedUs(childRepairStart, SteadyClock::now());
      }
    }
    NDN_LOG_TRACE("event=piggyback_recv_children mappings=" << mappingCount
                  << " data=" << dataCount
                  << " repairs=" << repairRequestCount);
  } catch (const std::exception&) {
  }

  bool queued = false;
  size_t processed = 0;
  const auto processStart = SteadyClock::now();
  for (const auto& [nodeId, bootstrapTime, seqNo] : receivedMappings) {
    try {
      queued |= processMapping(nodeId, bootstrapTime, seqNo);
      ++processed;
    }
    catch (const std::exception&) {
    }
  }
  const auto processDone = SteadyClock::now();
  if (queued) {
    fetchAll();
  }
  if (!receivedMappings.empty()) {
    NDN_LOG_TRACE("event=piggyback_process_mappings processed=" << processed
                  << " received=" << receivedMappings.size()
                  << " queued=" << queued);
  }
  NDN_LOG_TRACE("event=extra_mapping_recv_timing bytes=" << block.size()
                << " top_level_mappings=" << topLevelMappings
                << " child_mappings=" << mappingCount
                << " child_data=" << dataCount
                << " child_repairs=" << repairRequestCount
                << " received_mappings=" << receivedMappings.size()
                << " processed=" << processed
                << " queued=" << queued
                << " top_level_parse_us=" << topLevelParseUs
                << " block_parse_us=" << blockParseUs
                << " child_mapping_parse_us=" << childMappingParseUs
                << " child_data_parse_us=" << childDataParseUs
                << " child_repair_parse_us=" << childRepairParseUs
                << " child_cache_us=" << childCacheUs
                << " process_mapping_us=" << elapsedUs(processStart, processDone)
                << " total_us=" << elapsedUs(totalStart, SteadyClock::now()));
}

} // namespace ndn::svs
