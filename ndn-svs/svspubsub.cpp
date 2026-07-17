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

#include <algorithm>
#include <chrono>

namespace ndn::svs {

NDN_LOG_INIT(ndn_svs.SVSPubSub);

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
  , m_maxApplicationParametersSize(std::max<size_t>(1, options.maxApplicationParametersSize))
  , m_maxPiggyDataSize(std::max<size_t>(1, options.maxPiggyDataSize))
  , m_piggyDataCacheLimit(std::max<size_t>(1, options.piggyDataCacheLimit))
{
  m_svsync.getCore().setGetExtraBlockCallback(std::bind(&SVSPubSub::onGetExtraData, this, _1));
  m_svsync.getCore().setRecvExtraBlockCallback(std::bind(&SVSPubSub::onRecvExtraData, this, _1, _2));
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
    SeqNo seqNo = m_svsync.getCore().getSeqNo(nid) + 1;

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
    insertMapping(nid, seqNo, name, mappingBlocks);
    m_svsync.getCore().updateSeqNo(seqNo, nid);
    return seqNo;
  } else {
    ndn::Data data(name);
    data.setContent(value);
    data.setFreshnessPeriod(freshnessPeriod);
    m_securityOptions.dataSigner->sign(data);
    // If the data is within the configured limit, add it to the piggyback queue.
    const auto wireSize = data.wireEncode().size();
    if (wireSize <= m_maxPiggyDataSize) {
      std::lock_guard<std::mutex> lock(m_extraDataMutex);
      m_piggyDataQueue.push_back({data, 0});
    }
    else {
      NDN_LOG_TRACE("event=piggyback_skip reason=data_too_large bytes=" << wireSize
                    << " limit=" << m_maxPiggyDataSize
                    << " data=" << data.getName());
    }
    return publishPacket(data, nodePrefix);
  }
}


SeqNo
SVSPubSub::publish(const Name& name,
                   const Name& nodePrefix, time::milliseconds freshnessPeriod,
                   std::vector<Block> mappingBlocks)
{
  // Segment the data if larger than MAX_DATA_SIZE
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo = m_svsync.getCore().getSeqNo(nid) + 1;

  // Insert mapping and manually update the sequence number
  insertMapping(nid, seqNo, name, mappingBlocks);
  m_svsync.getCore().updateSeqNo(seqNo, nid);

  return seqNo;
}

SeqNo
SVSPubSub::publishPacket(const Data& data, const Name& nodePrefix, std::vector<Block> mappingBlocks)
{
  NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  SeqNo seqNo = m_svsync.publishData(data.wireEncode(), data.getFreshnessPeriod(), nid, ndn::tlv::Data);
  insertMapping(nid, seqNo, data.getName(), mappingBlocks);
  return seqNo;
}

void
SVSPubSub::insertMapping(const NodeID& nid, SeqNo seqNo, const Name& name, std::vector<Block> additional)
{
  // additional is a copy deliberately
  // this way we can add well-known mappings to the list

  // add timestamp block
  if (m_opts.useTimestamp) {
    unsigned long now = std::chrono::duration_cast<std::chrono::microseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    auto timestamp = Name::Component::fromNumber(now, ndn::tlv::TimestampNameComponent);
    additional.push_back(timestamp);
  }

  // create mapping entry
  MappingEntryPair entry = { name, additional };

  // notify subscribers in next sync interest
  if (m_notificationMappingList.nodeId == EMPTY_NAME || m_notificationMappingList.nodeId == nid) {
    m_notificationMappingList.nodeId = nid;
    m_notificationMappingList.pairs.push_back({ seqNo, entry });
  }

  // send mapping to provider
  m_mappingProvider.insertMapping(nid, seqNo, entry);
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
          m_fetchMap[std::pair(stream.nodeId, i)].push_back(sub);

        // Prefetch next available data
        if (sub.prefetch)
          m_svsync.fetchData(stream.nodeId, stream.high + 1, [](auto&&...) {}); // do nothing with prefetch
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
          this->processMapping(stream.nodeId, i);
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

        m_mappingProvider.fetchNameMapping(
          truncatedRemainingInfo,
          [this, remainingInfo, streamName](const MappingList& list) {
            bool queued = false;
            for (const auto& [seq, mapping] : list.pairs)
              queued |= this->processMapping(streamName, seq);

            if (queued)
              this->fetchAll();
          },
          -1);

        remainingInfo.low += 11;
      }
    }
  }

  fetchAll();
  m_onUpdate(info);
}

bool
SVSPubSub::processMapping(const NodeID& nodeId, SeqNo seqNo)
{
  const std::pair<Name, SeqNo> publication(nodeId, seqNo);
  if (hasPiggyDeliveredPublication(publication)) {
    return false;
  }

  // this will throw if mapping not found
  auto mapping = m_mappingProvider.getMapping(nodeId, seqNo);

  // check if timestamp is too old
  if (m_opts.maxPubAge > 0_ms) {
    // look for the additional timestamp block
    // if no timestamp block is present, we just skip this step
    for (const auto& block : mapping.second) {
      if (block.type() != ndn::tlv::TimestampNameComponent)
        continue;

      unsigned long now = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();

      unsigned long pubTime = Name::Component(block).toNumber();
      unsigned long maxAge = time::microseconds(m_opts.maxPubAge).count();

      if (now - pubTime > maxAge)
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
        else if (data != m_piggyDataCache.end() && mapping.first.isPrefixOf(data->first)) {
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
SVSPubSub::fetchAll()
{
  using PendingFetchKey = decltype(m_fetchMap)::key_type;
  std::vector<PendingFetchKey> pendingFetches;
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
    const auto& [nodeId, seqNo] = key;
    try {
      const auto mapping = m_mappingProvider.getMapping(nodeId, seqNo);
      std::optional<Data> packet;
      {
        std::lock_guard<std::mutex> lock(m_extraDataMutex);
        auto data = m_piggyDataCache.lower_bound(mapping.first);
        auto exactData = m_piggyDataCache.find(mapping.first);
        if (exactData != m_piggyDataCache.end()) {
          packet = exactData->second;
        }
        else if (data != m_piggyDataCache.end() && mapping.first.isPrefixOf(data->first)) {
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
                      << " node=" << nodeId << " seq=" << seqNo);
        cleanUpFetch(key);
        continue;
      }
    }
    catch (const std::exception&) {
    }
    m_svsync.fetchData(nodeId, seqNo, std::bind(&SVSPubSub::onSyncData, this, _1, key), 12);
  }
}

void
SVSPubSub::onSyncData(const Data& firstData, const std::pair<Name, SeqNo>& publication)
{
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
    innerData.getName(), innerContent.value_bytes(), publication.first, publication.second, innerData,
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
                innerName, *finalBuffer, publication.first, publication.second, std::nullopt,
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
SVSPubSub::cleanUpFetch(const std::pair<Name, SeqNo>& publication)
{
  m_fetchMap.erase(publication);
  m_fetchingMap.erase(publication);
}

bool
SVSPubSub::hasPiggyDeliveredPublication(const std::pair<Name, SeqNo>& publication)
{
  std::lock_guard<std::mutex> lock(m_extraDataMutex);
  return m_piggyDeliveredPublications.find(publication) != m_piggyDeliveredPublications.end();
}

void
SVSPubSub::rememberPiggyDeliveredPublication(const std::pair<Name, SeqNo>& publication)
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
  std::vector<std::pair<std::pair<Name, SeqNo>, std::vector<Subscription>>> ready;

  for (const auto& entry : m_fetchMap)
  {
    const auto& publication = entry.first;
    try {
      auto mapping = m_mappingProvider.getMapping(publication.first, publication.second);
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
      publication.first,
      publication.second,
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
      if (candidateBlock.size() <= m_maxApplicationParametersSize) {
        includedMappings = std::move(candidate);
        ++mappingCount;
      }
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
    if (size + dataBlock.size() > m_maxApplicationParametersSize) {
      ++it->missed;
      if (it->missed < 3) {
        retained.push_front(*it);
        ++retainedCount;
      }
      else {
        ++expiredCount;
        NDN_LOG_TRACE("event=piggyback_drop reason=missed_too_many bytes="
                      << dataBlock.size() << " data=" << it->data.getName());
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
                << " appParamLimit=" << m_maxApplicationParametersSize
                << " piggyDataLimit=" << m_maxPiggyDataSize);

  m_notificationMappingList = MappingList();

  return block;
}

void
SVSPubSub::onRecvExtraData(const Block& block, const VersionVector&)
{
  std::vector<std::pair<NodeID, SeqNo>> receivedMappings;
  try {
    NDN_LOG_TRACE("event=piggyback_recv_block type=" << block.type()
                  << " bytes=" << block.size());
    MappingList list(block);
    for (const auto& p : list.pairs) {
      m_mappingProvider.insertMapping(list.nodeId, p.first, p.second);
      receivedMappings.emplace_back(list.nodeId, p.first);
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
        for (const auto& p : childList.pairs) {
          m_mappingProvider.insertMapping(childList.nodeId, p.first, p.second);
          receivedMappings.emplace_back(childList.nodeId, p.first);
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
  for (const auto& [nodeId, seqNo] : receivedMappings) {
    try {
      queued |= processMapping(nodeId, seqNo);
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
