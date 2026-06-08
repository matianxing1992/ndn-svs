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
#include <cstdlib>
#include <set>

namespace ndn::svs {

NDN_LOG_INIT(ndn_svs.SVSPubSub);

namespace {

size_t
envSizeOrDefault(const char* name, size_t defaultValue)
{
  const char* value = std::getenv(name);
  if (value == nullptr || *value == '\0') {
    return defaultValue;
  }
  try {
    return std::max<size_t>(1, static_cast<size_t>(std::stoull(value)));
  }
  catch (...) {
    return defaultValue;
  }
}

} // namespace

SVSPubSub::SVSPubSub(const Name& syncPrefix,
                     const Name& nodePrefix,
                     ndn::Face& face,
                     UpdateCallback updateCallback,
                     const SVSPubSubOptions& options,
                     const SecurityOptions& securityOptions)
  : m_face(face)
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
             options.dataStore)
  , m_mappingProvider(syncPrefix, nodePrefix, face, securityOptions)
  , m_asyncPublishWorkers(4)
  , m_asyncPublishAlive(std::make_shared<std::atomic_bool>(true))
{
  MAX_SIZE_OF_APPLICATION_PARAMETERS =
    envSizeOrDefault("NDNSF_SVS_MAX_APP_PARAMS_BYTES",
                     MAX_SIZE_OF_APPLICATION_PARAMETERS);
  MAX_SIZE_OF_PIGGYDATA =
    envSizeOrDefault("NDNSF_SVS_MAX_PIGGYDATA_BYTES",
                     MAX_SIZE_OF_PIGGYDATA);
  m_piggyDataCacheLimit =
    envSizeOrDefault("NDNSF_SVS_PIGGYDATA_CACHE_LIMIT",
                     m_piggyDataCacheLimit);
  m_svsync.getCore().setGetExtraBlockCallback(std::bind(&SVSPubSub::onGetExtraData, this, _1));
  m_svsync.getCore().setRecvExtraBlockCallback(std::bind(&SVSPubSub::onRecvExtraData, this, _1, _2));
}

SVSPubSub::~SVSPubSub()
{
  if (m_asyncPublishAlive) {
    m_asyncPublishAlive->store(false, std::memory_order_relaxed);
  }
  m_asyncPublishWorkers.stop();
  m_asyncPublishWorkers.join();
}

SeqNo
SVSPubSub::publish(const Name& name,
                   span<const uint8_t> value,
                   const Name& nodePrefix,
                   time::milliseconds freshnessPeriod,
                   std::vector<Block> mappingBlocks)
{
  // Segment the data if larger than MAX_DATA_SIZE
  if (value.size() > MAX_DATA_SIZE) {
    size_t nSegments = (value.size() / MAX_DATA_SIZE) + 1;
    auto finalBlock = name::Component::fromSegment(nSegments - 1);

    NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
    SeqNo seqNo = reserveSeqNo(nid);
    BootstrapTime bootstrapTime = m_svsync.getCore().getBootstrapTime();

    for (size_t i = 0; i < nSegments; i++) {
      // Create encapsulated segment
      auto segmentName = Name(name).appendVersion(0).appendSegment(i);
      auto segment = Data(segmentName);
      segment.setFreshnessPeriod(freshnessPeriod);

      const uint8_t* segVal = value.data() + i * MAX_DATA_SIZE;
      const size_t segValSize = std::min(value.size() - i * MAX_DATA_SIZE, MAX_DATA_SIZE);
      segment.setContent(ndn::make_span(segVal, segValSize));

      segment.setFinalBlock(finalBlock);
      m_securityOptions.dataSigner->sign(segment);

      // Insert outer segment
      m_svsync.insertDataSegment(
        segment.wireEncode(), freshnessPeriod, nid, seqNo, i, finalBlock, ndn::tlv::Data);
    }

    // Insert mapping and manually update the sequence number
    insertMapping(nid, bootstrapTime, seqNo, name, mappingBlocks);
    m_svsync.getCore().updateSeqNo(seqNo, nid);
    return seqNo;
  } else {
    ndn::Data data(name);
    data.setContent(value);
    data.setFreshnessPeriod(freshnessPeriod);
    m_securityOptions.dataSigner->sign(data);
    // if the data size is smaller than MAX_SIZE_OF_PIGGYDATA, add it to the piggyback queue
    const auto wireSize = data.wireEncode().size();
    if (wireSize <= MAX_SIZE_OF_PIGGYDATA) {
      std::lock_guard<std::mutex> lock(m_extraDataMutex);
      m_piggyDataQueue.push_back({data, 0});
    }
    else {
      NDN_LOG_TRACE("event=piggyback_skip reason=data_too_large bytes=" << wireSize
                    << " limit=" << MAX_SIZE_OF_PIGGYDATA
                    << " data=" << data.getName());
    }
    return publishPacket(data, nodePrefix);
  }
}

SeqNo
SVSPubSub::publishAsync(const Name& name, span<const uint8_t> value,
                        const Name& nodePrefix, time::milliseconds freshnessPeriod,
                        std::vector<Block> mappingBlocks)
{
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo = reserveSeqNo(nid);

  AsyncPublication publication;
  publication.kind = AsyncPublication::Kind::Bytes;
  publication.bootstrapTime = m_svsync.getCore().getBootstrapTime();
  publication.seqNo = seqNo;
  publication.name = name;
  publication.nodePrefix = nid;
  publication.freshnessPeriod = freshnessPeriod;
  publication.value.assign(value.begin(), value.end());
  publication.mappingBlocks = std::move(mappingBlocks);
  enqueueAsyncPublication(std::move(publication));

  return seqNo;
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
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo = reserveSeqNo(nid);

  AsyncPublication publication;
  publication.kind = AsyncPublication::Kind::NameOnly;
  publication.bootstrapTime = m_svsync.getCore().getBootstrapTime();
  publication.seqNo = seqNo;
  publication.name = name;
  publication.nodePrefix = nid;
  publication.freshnessPeriod = freshnessPeriod;
  publication.mappingBlocks = std::move(mappingBlocks);
  enqueueAsyncPublication(std::move(publication));

  return seqNo;
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
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo = reserveSeqNo(nid);

  AsyncPublication publication;
  publication.kind = AsyncPublication::Kind::Packet;
  publication.bootstrapTime = m_svsync.getCore().getBootstrapTime();
  publication.seqNo = seqNo;
  publication.name = data.getName();
  publication.nodePrefix = nid;
  publication.freshnessPeriod = data.getFreshnessPeriod();
  publication.packet = data;
  publication.mappingBlocks = std::move(mappingBlocks);
  enqueueAsyncPublication(std::move(publication));

  return seqNo;
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

void
SVSPubSub::enqueueAsyncPublication(AsyncPublication publication)
{
  auto alive = m_asyncPublishAlive;
  boost::asio::post(m_asyncPublishWorkers,
                    [this, alive, publication = std::move(publication)] () mutable {
                      if (!alive || !alive->load(std::memory_order_relaxed)) {
                        return;
                      }
                      prepareAsyncPublication(std::move(publication));
                    });
}

void
SVSPubSub::prepareAsyncPublication(AsyncPublication publication)
{
  PreparedPublication prepared;
  try {
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
  }
  catch (const std::exception& e) {
    NDN_LOG_DEBUG("event=async_publish_prepare_failed node=" << publication.nodePrefix
                  << " seq=" << publication.seqNo << " error=" << e.what());
    prepared.seqNo = publication.seqNo;
    prepared.nodePrefix = publication.nodePrefix;
    prepared.ok = false;
  }

  auto alive = m_asyncPublishAlive;
  boost::asio::post(m_face.getIoContext(), [this, alive, prepared = std::move(prepared)] () mutable {
    if (!alive || !alive->load(std::memory_order_relaxed)) {
      return;
    }
    onPreparedPublication(std::move(prepared));
  });
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

  if (publication.value.size() > MAX_DATA_SIZE) {
    size_t nSegments = (publication.value.size() / MAX_DATA_SIZE) + 1;
    auto finalBlock = name::Component::fromSegment(nSegments - 1);

    for (size_t i = 0; i < nSegments; i++)
    {
      auto segmentName = Name(publication.name).appendVersion(0).appendSegment(i);
      auto segment = Data(segmentName);
      segment.setFreshnessPeriod(publication.freshnessPeriod);

      const uint8_t* segVal = publication.value.data() + i * MAX_DATA_SIZE;
      const size_t segValSize = std::min(publication.value.size() - i * MAX_DATA_SIZE,
                                         MAX_DATA_SIZE);
      segment.setContent(ndn::make_span(segVal, segValSize));

      segment.setFinalBlock(finalBlock);
      {
        std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
        m_securityOptions.dataSigner->sign(segment);
      }

      Data outer(m_svsync.getDataName(publication.nodePrefix, publication.bootstrapTime,
                                      publication.seqNo)
                   .appendVersion(0).appendSegment(i));
      outer.setContent(segment.wireEncode());
      outer.setFreshnessPeriod(publication.freshnessPeriod);
      outer.setContentType(ndn::tlv::Data);
      outer.setFinalBlock(finalBlock);
      {
        std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
        m_securityOptions.dataSigner->sign(outer);
      }
      outer.wireEncode();
      m_svsync.insertPreparedData(outer, false);
      prepared.outerPackets.push_back(std::move(outer));
    }

    insertMapping(publication.nodePrefix, publication.bootstrapTime, publication.seqNo,
                  publication.name, publication.mappingBlocks);
    return prepared;
  }

  ndn::Data data(publication.name);
  data.setContent(make_span(publication.value.data(), publication.value.size()));
  data.setFreshnessPeriod(publication.freshnessPeriod);
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishSigningMutex);
    m_securityOptions.dataSigner->sign(data);
  }
  const auto wireSize = data.wireEncode().size();
  if (wireSize <= MAX_SIZE_OF_PIGGYDATA) {
    prepared.piggyPacket = data;
  }
  else {
    NDN_LOG_TRACE("event=piggyback_skip reason=data_too_large bytes=" << wireSize
                  << " limit=" << MAX_SIZE_OF_PIGGYDATA
                  << " data=" << data.getName());
  }

  AsyncPublication packetPublication;
  packetPublication.kind = AsyncPublication::Kind::Packet;
  packetPublication.bootstrapTime = publication.bootstrapTime;
  packetPublication.seqNo = publication.seqNo;
  packetPublication.name = data.getName();
  packetPublication.nodePrefix = publication.nodePrefix;
  packetPublication.freshnessPeriod = data.getFreshnessPeriod();
  packetPublication.packet = data;
  packetPublication.mappingBlocks = publication.mappingBlocks;
  auto packetPrepared = prepareReservedPacket(packetPublication);
  packetPrepared.piggyPacket = prepared.piggyPacket;
  return packetPrepared;
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
  insertMapping(publication.nodePrefix, publication.bootstrapTime, publication.seqNo,
                publication.name, publication.mappingBlocks);
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
  m_svsync.insertPreparedData(outer, false);
  prepared.outerPackets.push_back(std::move(outer));
  insertMapping(publication.nodePrefix, publication.bootstrapTime, publication.seqNo,
                publication.packet.getName(), publication.mappingBlocks);
  return prepared;
}

void
SVSPubSub::onPreparedPublication(PreparedPublication publication)
{
  const auto nodePrefix = publication.nodePrefix;
  {
    std::lock_guard<std::mutex> lock(m_asyncPublishMutex);
    m_preparedPublications[nodePrefix][publication.seqNo] = std::move(publication);
  }
  commitReadyPreparedPublications(nodePrefix);
}

void
SVSPubSub::commitReadyPreparedPublications(const NodeID& nid)
{
  std::vector<PreparedPublication> ready;
  SeqNo highestSeq = 0;
  while (true) {
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
      highestSeq = pubIt->second.seqNo;
      ready.push_back(std::move(pubIt->second));
      nodeIt->second.erase(pubIt);
      if (nodeIt->second.empty()) {
        m_preparedPublications.erase(nodeIt);
      }
      ++nextIt->second;
    }
  }

  if (ready.empty()) {
    return;
  }

  for (const auto& publication : ready) {
    commitPreparedPublication(publication);
  }
  m_svsync.getCore().updateSeqNo(highestSeq, nid);
}

void
SVSPubSub::commitPreparedPublication(const PreparedPublication& publication)
{
  if (!publication.ok) {
    return;
  }

  if (publication.putFirstPacketToFace && !publication.outerPackets.empty()) {
    m_svsync.putPreparedData(publication.outerPackets.front());
  }

  if (publication.piggyPacket) {
    std::lock_guard<std::mutex> lock(m_extraDataMutex);
    m_piggyDataQueue.push_back({*publication.piggyPacket, 0});
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
          m_fetchMap[PublicationKey(stream.nodeId, stream.bootstrapTime, i)].push_back(sub);

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
        m_fetchMap[publication].push_back(sub);
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
SVSPubSub::fetchAll()
{
  std::vector<PublicationKey> pendingFetches;
  pendingFetches.reserve(m_fetchMap.size());
  for (const auto& pair : m_fetchMap) {
    pendingFetches.push_back(pair.first);
  }

  for (const auto& key : pendingFetches) {
    if (m_fetchMap.find(key) == m_fetchMap.end())
      continue;
    if (m_fetchingMap.find(key) != m_fetchingMap.end())
      continue;
    m_fetchingMap[key] = true;

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
        cleanUpFetch(key);
        continue;
      }
    }
    catch (const std::exception&) {
    }
    m_svsync.fetchData(nodeId, bootstrapTime, seqNo,
                       std::bind(&SVSPubSub::onSyncData, this, _1, key), 12);
  }
}

void
SVSPubSub::onSyncData(const Data& firstData, const PublicationKey& publication)
{
  const auto& nodeId = std::get<0>(publication);
  const auto seqNo = std::get<2>(publication);

  // Make sure the data is encapsulated
  if (firstData.getContentType() != ndn::tlv::Data) {
    m_fetchingMap[publication] = false;
    return;
  }

  // Unwrap
  Data innerData(firstData.getContent().blockFromValue());
  auto innerContent = innerData.getContent();

  // Return data to packet subscriptions
  SubscriptionData subData = {
    innerData.getName(), innerContent.value_bytes(), nodeId, seqNo, innerData,
  };

  // Function to return data to subscriptions
  auto returnData = [this, firstData, subData, publication]() {
    bool hasFinalBlock = subData.packet.value().getFinalBlock().has_value();
    bool hasBlobSubcriptions = false;

    for (const auto& sub : this->m_fetchMap[publication]) {
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

      fetcher->onComplete.connectSingleShot([this, publication](const ndn::ConstBufferPtr& data) {
        try {
          // Binary BLOB to return to app
          auto finalBuffer = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(data->size()));
          auto bufSize = std::make_shared<size_t>(0);
          bool hasValidator = !!m_securityOptions.encapsulatedDataValidator;

          // Read all TLVs as Data packets till the end of data buffer
          ndn::Block block(6, data);
          block.parse();

          // Number of elements validated / failed to validate
          auto numValidated = std::make_shared<size_t>(0);
          auto numFailed = std::make_shared<size_t>(0);
          auto numElem = block.elements_size();

          if (numElem == 0)
            return this->cleanUpFetch(publication);

          // Get name of inner data
          auto innerName = Data(block.elements()[0]).getName().getPrefix(-2);

          // Function to send final buffer to subscriptions if possible
          auto sendFinalBuffer =
            [this, innerName, publication, finalBuffer, bufSize, numFailed, numValidated, numElem] {
              if (*numValidated + *numFailed != numElem)
                return;

              if (*numFailed > 0) // abort
                return this->cleanUpFetch(publication);

              // Resize buffer to actual size
              finalBuffer->resize(*bufSize);

              // Return data to packet subscriptions
              SubscriptionData subData = {
                innerName, *finalBuffer, std::get<0>(publication), std::get<2>(publication),
                std::nullopt,
              };

              for (const auto& sub : this->m_fetchMap[publication])
                if (!sub.isPacketSubscription)
                  sub.callback(subData);

              this->cleanUpFetch(publication);
            };

          for (size_t i = 0; i < numElem; i++) {
            Data innerData(block.elements()[i]);

            // Copy actual binary data to final buffer
            auto size = innerData.getContent().value_size();
            std::memcpy(finalBuffer->data() + *bufSize, innerData.getContent().value(), size);
            *bufSize += size;

            // Validate inner data
            if (hasValidator) {
              this->m_securityOptions.encapsulatedDataValidator->validate(
                innerData,
                [sendFinalBuffer, numValidated](auto&&...) {
                  *numValidated += 1;
                  sendFinalBuffer();
                },
                [sendFinalBuffer, numFailed](auto&&...) {
                  *numFailed += 1;
                  sendFinalBuffer();
                });
            } else {
              *numValidated += 1;
            }
          }

          sendFinalBuffer();
        } catch (const std::exception&) {
          cleanUpFetch(publication);
        }
      });
      fetcher->onError.connectSingleShot(std::bind(&SVSPubSub::cleanUpFetch, this, publication));
    } else {
      cleanUpFetch(publication);
    }
  };

  // Validate encapsulated packet
  if (m_securityOptions.encapsulatedDataValidator) {
    m_securityOptions.encapsulatedDataValidator->validate(
      innerData, [&](auto&&...) { returnData(); }, [](auto&&...) {});
  } else {
    returnData();
  }
}

void
SVSPubSub::cleanUpFetch(const PublicationKey& publication)
{
  m_fetchMap.erase(publication);
  m_fetchingMap.erase(publication);
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
  std::lock_guard<std::mutex> lock(m_extraDataMutex);

  MappingList includedMappings(m_notificationMappingList.nodeId);
  size_t mappingCount = 0;
  size_t piggyCount = 0;
  if (m_notificationMappingList.nodeId != EMPTY_NAME) {
    for (const auto& entry : m_notificationMappingList.pairs) {
      MappingList candidate = includedMappings;
      candidate.pairs.push_back(entry);
      auto candidateBlock = candidate.encode();
      if (candidateBlock.size() <= MAX_SIZE_OF_APPLICATION_PARAMETERS) {
        includedMappings = std::move(candidate);
        ++mappingCount;
      }
      // Overflow mappings are intentionally omitted from this latency-oriented
      // piggyback path; peers can still fetch them from MappingProvider.
    }
  }

  ndn::Block block = includedMappings.encode();
  block.parse();
  size_t size = block.size();
  size_t retainedCount = 0;
  size_t expiredCount = 0;
  std::deque<PiggyDataEntry> retained;
  for (auto it = m_piggyDataQueue.rbegin(); it != m_piggyDataQueue.rend(); ++it) {
    auto dataBlock = it->data.wireEncode();
    if (size + dataBlock.size() > MAX_SIZE_OF_APPLICATION_PARAMETERS) {
      ++it->missed;
      if (it->missed < 3) {
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
  }
  m_piggyDataQueue = std::move(retained);
  block.encode();

  NDN_LOG_TRACE("event=piggyback_build mappings=" << mappingCount
                << " data=" << piggyCount
                << " retained=" << retainedCount
                << " expired=" << expiredCount
                << " bytes=" << block.size()
                << " appParamLimit=" << MAX_SIZE_OF_APPLICATION_PARAMETERS
                << " piggyDataLimit=" << MAX_SIZE_OF_PIGGYDATA);

  m_notificationMappingList = MappingList();

  return block;
}

void
SVSPubSub::onRecvExtraData(const Block& block, const VersionVector&)
{
  std::vector<PublicationKey> receivedMappings;
  try {
    NDN_LOG_TRACE("event=piggyback_recv_block type=" << block.type()
                  << " bytes=" << block.size());
    MappingList list(block);
    for (const auto& entry : list.pairs) {
      m_mappingProvider.insertMapping(list.nodeId, entry.bootstrapTime, entry.seqNo, entry.mapping);
      receivedMappings.emplace_back(list.nodeId, entry.bootstrapTime, entry.seqNo);
    }
    NDN_LOG_TRACE("event=piggyback_recv_mapping_list node=" << list.nodeId
                  << " mappings=" << list.pairs.size());
  } catch (const std::exception& e) {
    NDN_LOG_TRACE("event=piggyback_recv_mapping_list_error error=" << e.what());
  }

  try {
    block.parse();
    size_t mappingCount = 0;
    size_t dataCount = 0;
    for (const auto& childBlock : block.elements()) {
      NDN_LOG_TRACE("event=piggyback_recv_child type=" << childBlock.type()
                    << " bytes=" << childBlock.size());
      if (childBlock.type() == ndn::svs::tlv::MappingData) {
        MappingList childList(childBlock);
        for (const auto& entry : childList.pairs) {
          m_mappingProvider.insertMapping(childList.nodeId, entry.bootstrapTime,
                                          entry.seqNo, entry.mapping);
          receivedMappings.emplace_back(childList.nodeId, entry.bootstrapTime, entry.seqNo);
        }
        mappingCount += childList.pairs.size();
      }

      if (childBlock.type() == ndn::tlv::Data) {
        ndn::Data data(childBlock);
        satisfyPendingFetchFromPiggyData(data);
        try {
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
        }
        catch (const std::exception&) {
        }
        ++dataCount;
      }
    }
    NDN_LOG_TRACE("event=piggyback_recv_children mappings=" << mappingCount
                  << " data=" << dataCount);
  } catch (const std::exception&) {
  }

  bool queued = false;
  size_t processed = 0;
  for (const auto& [nodeId, bootstrapTime, seqNo] : receivedMappings) {
    try {
      queued |= processMapping(nodeId, bootstrapTime, seqNo);
      ++processed;
    }
    catch (const std::exception&) {
    }
  }
  if (queued) {
    fetchAll();
  }
  if (!receivedMappings.empty()) {
    NDN_LOG_TRACE("event=piggyback_process_mappings processed=" << processed
                  << " received=" << receivedMappings.size()
                  << " queued=" << queued);
  }
}

} // namespace ndn::svs
