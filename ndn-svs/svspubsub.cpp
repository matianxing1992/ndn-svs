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

#include <ndn-cxx/security/certificate-fetcher-offline.hpp>
#include <ndn-cxx/util/segment-fetcher.hpp>

#include <limits>

namespace ndn::svs {

namespace {

// Adapt the configured validators to SegmentFetcher without bypassing either layer.
class PublicationPolicy : public security::ValidationPolicy
{
public:
  PublicationPolicy(const SecurityOptions& options, const Name& name)
    : m_outer(options.validator)
    , m_inner(options.encapsulatedDataValidator)
    , m_name(name)
  {
  }

  void
  checkPolicy(const Data& data,
              const std::shared_ptr<security::ValidationState>& state,
              const ValidationContinuation& next) override
  {
    const std::weak_ptr<int> lifetime = m_lifetime;
    auto fail = [state, lifetime] (const Data&, const auto& error) {
      if (!lifetime.expired())
        state->fail(error);
    };
    auto acceptOuter =
      [inner = m_inner, name = m_name, state, next, lifetime, fail] (const Data& outer) {
        if (lifetime.expired())
          return;
        try {
          if (outer.getContentType() != ndn::tlv::Data)
            NDN_THROW(std::invalid_argument("publication is not encapsulated Data"));
          Data packet(outer.getContent().blockFromValue());
          const bool hasMatchingFinalBlock =
            outer.getFinalBlock() && outer.getFinalBlock() == packet.getFinalBlock();
          const bool hasSegmentNames = hasMatchingFinalBlock && outer.getName().size() >= 2 &&
                                       packet.getName().size() >= 2 &&
                                       outer.getName()[-1].isSegment();
          if (!hasMatchingFinalBlock || !hasSegmentNames)
            NDN_THROW(std::invalid_argument("inconsistent encapsulated segment"));
          const bool hasExpectedName = packet.getName().getPrefix(-2) == name;
          const bool hasMatchingSegment = outer.getName()[-1] == packet.getName()[-1];
          const bool hasMatchingVersion = outer.getName()[-2] == name::Component::fromVersion(0) &&
                                          packet.getName()[-2] == name::Component::fromVersion(0);
          if (!hasExpectedName || !hasMatchingSegment || !hasMatchingVersion)
            NDN_THROW(std::invalid_argument("inconsistent encapsulated segment"));
          if (inner)
            inner->validate(
              packet,
              [state, next, lifetime] (const Data&) {
                if (!lifetime.expired())
                  next(nullptr, state);
              },
              fail);
          else
            next(nullptr, state);
        }
        catch (const std::exception& error) {
          if (!lifetime.expired())
            state->fail({security::ValidationError::POLICY_ERROR, error.what()});
        }
      };
    auto outer = m_outer;
    if (outer)
      outer->validate(data, acceptOuter, fail);
    else
      acceptOuter(data);
  }

  void
  checkPolicy(const Interest&,
              const std::shared_ptr<security::ValidationState>& state,
              const ValidationContinuation&) override
  {
    state->fail({security::ValidationError::POLICY_ERROR, "expected publication Data"});
  }

private:
  const std::shared_ptr<BaseValidator> m_outer;
  const std::shared_ptr<BaseValidator> m_inner;
  const Name m_name;
  std::shared_ptr<int> m_lifetime = std::make_shared<int>(0);
};

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
             options.dataStore,
             options.bootstrapTime)
  , m_scheduler(m_face.getIoContext())
  , m_mappingProvider(syncPrefix, nodePrefix, face, securityOptions)
{
  if (m_opts.useMappingPiggyback)
    m_svsync.getCore().setGetExtraBlockCallback(std::bind(&SVSPubSub::onGetExtraData, this, _1));
  m_svsync.getCore().setRecvExtraBlockCallback(
    std::bind(&SVSPubSub::onRecvExtraData, this, _1, _2));
}

SVSPubSub::~SVSPubSub()
{
  m_lifetime.reset();
  for (const auto& entry : m_segmentFetchers)
    entry.second->stop();
}

SeqNo
SVSPubSub::publish(const Name& name,
                   span<const uint8_t> value,
                   const Name& nodePrefix,
                   time::milliseconds freshnessPeriod,
                   std::vector<Block> mappingBlocks)
{
  std::lock_guard<std::mutex> lock(m_svsync.m_publicationMutex);
  const NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  const auto bootstrapTime = m_svsync.getCore().getBootstrapTime();
  const SeqNo previous = m_svsync.getCore().getSeqNo(nid);
  if (previous == std::numeric_limits<SeqNo>::max())
    NDN_THROW(std::overflow_error("publication sequence number is exhausted"));
  const SeqNo seqNo = previous + 1;
  const auto limit = std::min(m_opts.maxPacketSize, ndn::MAX_NDN_PACKET_SIZE);
  std::shared_ptr<const Data> outer;
  std::vector<std::shared_ptr<const Data>> packets;
  if (value.size() <= limit) {
    Data packet(name);
    packet.setContent(value);
    packet.setFreshnessPeriod(freshnessPeriod);
    m_securityOptions.pubSigner->sign(packet);
    outer = m_svsync.prepareDataPacket(packet.wireEncode(),
                                       std::max(freshnessPeriod, 1_ms),
                                       nid,
                                       seqNo,
                                       std::nullopt,
                                       std::nullopt,
                                       ndn::tlv::Data,
                                       limit);
  }

  if (!outer) {
    size_t chunkSize = std::min(MAX_DATA_SIZE, limit);
    while (true) {
      packets.clear();
      if (chunkSize == 0 || value.empty())
        NDN_THROW(std::length_error("publication headers exceed the packet size limit"));
      const size_t count = value.size() / chunkSize + (value.size() % chunkSize != 0);
      const auto finalBlock = name::Component::fromSegment(count - 1);
      bool doesFit = true;
      for (size_t i = 0; i < count; ++i) {
        Data packet(Name(name).appendVersion(0).appendSegment(i));
        packet.setFreshnessPeriod(freshnessPeriod);
        packet.setFinalBlock(finalBlock);
        packet.setContent(
          value.subspan(i * chunkSize, std::min(chunkSize, value.size() - i * chunkSize)));
        m_securityOptions.pubSigner->sign(packet);
        auto segment = m_svsync.prepareDataPacket(packet.wireEncode(),
                                                  std::max(freshnessPeriod, 1_ms),
                                                  nid,
                                                  seqNo,
                                                  i,
                                                  finalBlock,
                                                  ndn::tlv::Data,
                                                  limit);
        if (!segment) {
          doesFit = false;
          break;
        }
        packets.push_back(std::move(segment));
      }
      if (doesFit)
        break;
      chunkSize /= 2;
    }
  }
  else {
    packets.push_back(outer);
  }

  insertMapping(nid, bootstrapTime, seqNo, name, mappingBlocks);
  for (const auto& packet : packets)
    m_svsync.getDataStore().insert(*packet);
  m_svsync.getCore().updateSeqNo(seqNo, nid);
  if (outer)
    m_face.put(*outer);
  return seqNo;
}

SeqNo
SVSPubSub::publishPacket(const Data& data, const Name& nodePrefix, std::vector<Block> mappingBlocks)
{
  std::lock_guard<std::mutex> lock(m_svsync.m_publicationMutex);
  if (data.getFinalBlock())
    NDN_THROW(std::invalid_argument(
      "publishPacket requires unsegmented Data; use publish for segmented blobs"));
  const NodeID nid = nodePrefix == EMPTY_NAME ? m_dataPrefix : nodePrefix;
  const SeqNo previous = m_svsync.getCore().getSeqNo(nid);
  if (previous == std::numeric_limits<SeqNo>::max())
    NDN_THROW(std::overflow_error("publication sequence number is exhausted"));
  const SeqNo seqNo = previous + 1;
  auto outer = m_svsync.prepareDataPacket(data.wireEncode(),
                                          std::max(data.getFreshnessPeriod(), 1_ms),
                                          nid,
                                          seqNo,
                                          std::nullopt,
                                          std::nullopt,
                                          ndn::tlv::Data,
                                          m_opts.maxPacketSize);
  if (!outer)
    NDN_THROW(std::length_error("publication exceeds the packet size limit"));
  insertMapping(nid, m_svsync.getCore().getBootstrapTime(), seqNo, data.getName(), mappingBlocks);
  m_svsync.getDataStore().insert(*outer);
  m_svsync.getCore().updateSeqNo(seqNo, nid);
  m_face.put(*outer);
  return seqNo;
}

void
SVSPubSub::insertMapping(const NodeID& nid,
                         BootstrapTime bootstrapTime,
                         SeqNo seqNo,
                         const Name& name,
                         std::vector<Block> additional)
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
  m_mappingProvider.addLocalNode(nid);
  m_mappingProvider.insertMapping(nid, bootstrapTime, seqNo, entry);

  // notify subscribers in next sync interest
  std::lock_guard<std::mutex> lock(m_notificationMutex);
  if (m_opts.useMappingPiggyback && (m_notificationMappingList.nodeId == EMPTY_NAME ||
                                     m_notificationMappingList.nodeId == nid)) {
    m_notificationMappingList.nodeId = nid;
    m_notificationMappingList.pairs.push_back({ seqNo, entry });
  }
}

uint32_t
SVSPubSub::subscribe(const Name& prefix, const SubscriptionCallback& callback, bool packets)
{
  uint32_t handle = ++m_subscriptionCount;
  Subscription sub = {handle, prefix, callback, packets, false, nullptr};
  m_prefixSubscriptions.push_back(sub);
  return handle;
}

uint32_t
SVSPubSub::subscribeWithRegex(const Regex& regex,
                              const SubscriptionCallback& callback,
                              bool packets)
{
  auto matcher = std::make_shared<Regex>(regex.getExpr());
  uint32_t handle = ++m_subscriptionCount;
  Subscription sub = {handle, Name(), callback, packets, false, std::move(matcher)};
  m_prefixSubscriptions.push_back(std::move(sub));
  return handle;
}

uint32_t
SVSPubSub::subscribeToProducer(const Name& nodePrefix,
                               const SubscriptionCallback& callback,
                               bool prefetch,
                               bool packets)
{
  uint32_t handle = ++m_subscriptionCount;
  Subscription sub = {handle, nodePrefix, callback, packets, prefetch, nullptr};
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
}

void
SVSPubSub::updateCallbackInternal(const std::vector<MissingDataInfo>& info)
{
  const std::weak_ptr<int> lifetime = m_lifetime;
  for (const auto& stream : info) {
    Name streamName(stream.nodeId);
    bool hasMatchingProducer = false;

    // Producer subscriptions
    for (const auto& sub : m_producerSubscriptions) {
      if (sub.prefix.isPrefixOf(streamName)) {
        hasMatchingProducer = true;
        // Add to fetching queue
        for (SeqNo i = stream.low;; ++i) {
          m_fetchMap[PublicationKey(stream.nodeId, stream.bootstrapTime, i)].push_back(sub);
          if (i == stream.high)
            break;
        }

        // Prefetch next available data
        if (sub.prefetch && stream.high != std::numeric_limits<SeqNo>::max())
          m_svsync.fetchData(stream.nodeId, stream.bootstrapTime, stream.high + 1, [] (auto&&...) {
          }); // do nothing with prefetch
      }
    }

    // Fetch all mappings if we have prefix subscription(s)
    if (!m_prefixSubscriptions.empty() &&
        (!hasMatchingProducer || m_opts.mappingFilter || m_opts.maxPubAge > 0_ms)) {
      MissingDataInfo remainingInfo = stream;

      // Attemt to find what we already know about mapping
      // This typically refers to the Sync Interest mapping optimization,
      // where the Sync Interest contains the notification mapping list
      bool isComplete = false;
      for (SeqNo i = remainingInfo.low;; ++i) {
        try {
          // throws if mapping not found
          this->processMapping(stream.nodeId, stream.bootstrapTime, i);
          if (lifetime.expired())
            return;
          if (i == remainingInfo.high) {
            isComplete = true;
            break;
          }
          remainingInfo.low = i + 1;
        } catch (const std::exception&) {
          break;
        }
      }

      // Find from network what we don't yet know
      while (!isComplete) {
        // Fetch a max of 10 entries per request
        // This is to ensure the mapping response does not overflow
        // TODO: implement a better solution to this issue
        MissingDataInfo truncatedRemainingInfo = remainingInfo;
        if (truncatedRemainingInfo.high - truncatedRemainingInfo.low > 10) {
          truncatedRemainingInfo.high = truncatedRemainingInfo.low + 10;
        }

        m_mappingProvider.fetchNameMapping(
          truncatedRemainingInfo,
          [this, lifetime, remainingInfo, streamName] (const MappingList& list) {
            bool queued = false;
            for (const auto& [seq, mapping] : list.pairs) {
              queued |= this->processMapping(streamName, remainingInfo.bootstrapTime, seq);
              if (lifetime.expired())
                return;
            }

            if (queued)
              this->fetchAll();
          },
          [callback = m_opts.onFetchError] (const Interest& interest) {
            if (callback)
              callback(interest.getName());
          },
          m_opts.mappingRetries);

        if (truncatedRemainingInfo.high == remainingInfo.high)
          break;
        remainingInfo.low = truncatedRemainingInfo.high + 1;
      }
    }
  }

  fetchAll();
  m_onUpdate(info);
}

bool
SVSPubSub::processMapping(const NodeID& nodeId, BootstrapTime bootstrapTime, SeqNo seqNo)
{
  // this will throw if mapping not found
  auto mapping = m_mappingProvider.getMapping(nodeId, bootstrapTime, seqNo);
  if (m_opts.mappingFilter) {
    const std::weak_ptr<int> lifetime = m_lifetime;
    auto filter = m_opts.mappingFilter;
    const bool isAccepted = filter(mapping.first, mapping.second);
    if (lifetime.expired() || !isAccepted)
      return false;
  }

  // check if timestamp is too old
  if (m_opts.maxPubAge > 0_ms) {
    // look for the additional timestamp block
    // if no timestamp block is present, we just skip this step
    for (const auto& block : mapping.second) {
      if (block.type() != tlv::TimestampNameComponent)
        continue;

      const auto pubTime = Name::Component(block).toTimestamp();
      if (time::system_clock::now() - pubTime > m_opts.maxPubAge)
        return false;
    }
  }

  // check if known mapping matches subscription
  bool queued = false;
  for (const auto& sub : m_prefixSubscriptions) {
    if (sub.matches(mapping.first)) {
      m_fetchMap[PublicationKey(nodeId, bootstrapTime, seqNo)].push_back(sub);
      queued = true;
    }
  }

  return queued;
}

std::vector<SVSPubSub::Subscription>
SVSPubSub::getSubscriptions(const PublicationKey& publication, const Name& name)
{
  std::vector<Subscription> subscriptions;
  bool hasMatchingMapping = false;
  try {
    const auto& [node, epoch, seq] = publication;
    hasMatchingMapping = m_mappingProvider.getMapping(node, epoch, seq).first == name;
  }
  catch (const std::out_of_range&) {
  }
  for (const auto& queued : m_fetchMap.at(publication)) {
    const bool isProducer = std::any_of(m_producerSubscriptions.begin(),
                                        m_producerSubscriptions.end(),
                                        [&] (const auto& sub) { return sub.id == queued.id; });
    const bool isTopic = std::any_of(
      m_prefixSubscriptions.begin(), m_prefixSubscriptions.end(), [&] (const auto& sub) {
        return sub.id == queued.id && sub.matches(name) && hasMatchingMapping;
      });
    if (isProducer || isTopic)
      subscriptions.push_back(queued);
  }
  // Producer fetches reveal the application name; topic delivery still needs mappings
  // when a mapping filter or publication-age limit is configured.
  if (!m_opts.mappingFilter && m_opts.maxPubAge == 0_ms) {
    for (const auto& sub : m_prefixSubscriptions) {
      if (sub.matches(name) &&
          std::none_of(subscriptions.begin(), subscriptions.end(), [&] (const auto& queued) {
            return queued.id == sub.id;
          }))
        subscriptions.push_back(sub);
    }
  }
  return subscriptions;
}

void
SVSPubSub::fetchAll()
{
  for (const auto& pair : m_fetchMap) {
    // Check if already fetching this publication
    auto key = pair.first;
    if (m_fetchingMap.find(key) != m_fetchingMap.end())
      continue;
    m_fetchingMap.try_emplace(key);

    fetchPublication(key, m_opts.dataRetries, m_securityOptions.nRetriesOnValidationFail);
  }
}

void
SVSPubSub::fetchPublication(const PublicationKey& key, int retries, int validationRetries)
{
  const auto& [nodeId, bootstrapTime, seqNo] = key;
  const std::weak_ptr<int> lifetime = m_lifetime;
  m_svsync.fetchData(
    nodeId,
    bootstrapTime,
    seqNo,
    [this, lifetime, key, retries, validationRetries] (const Data& data) {
      if (!lifetime.expired())
        onSyncData(data, key, retries, validationRetries);
    },
    [this, lifetime, key] (auto&&...) {
      if (!lifetime.expired())
        failFetch(key);
    },
    [this, lifetime, key] (auto&&...) {
      if (!lifetime.expired())
        failFetch(key);
    },
    retries);
}

void
SVSPubSub::onSyncData(const Data& firstData,
                      const PublicationKey& publication,
                      int retries,
                      int validationRetries)
{
  const std::weak_ptr<int> lifetime = m_lifetime;
  try {
    if (firstData.getContentType() != ndn::tlv::Data)
      NDN_THROW(std::invalid_argument("publication is not encapsulated Data"));
    Data innerData(firstData.getContent().blockFromValue());
    const auto expected = m_svsync.getDataName(
      std::get<0>(publication), std::get<1>(publication), std::get<2>(publication));

    if (firstData.getFinalBlock()) {
      if (firstData.getName().size() != expected.size() + 2 ||
          firstData.getName().getPrefix(-2) != expected || innerData.getName().size() < 2 ||
          !firstData.getName()[-1].isSegment() ||
          firstData.getName()[-2] != name::Component::fromVersion(0))
        NDN_THROW(std::invalid_argument("invalid segmented publication name"));

      Interest interest(firstData.getName().getPrefix(-1));
      auto validator = std::make_shared<security::Validator>(
        std::make_unique<PublicationPolicy>(m_securityOptions, innerData.getName().getPrefix(-2)),
        std::make_unique<security::CertificateFetcherOffline>());
      auto fetcher = ndn::SegmentFetcher::start(m_face, interest, *validator);
      m_segmentFetchers[publication] = fetcher;
      fetcher->afterSegmentValidated.connect([this, lifetime, publication] (const Data& outer) {
        if (lifetime.expired())
          return;
        Data packet(outer.getContent().blockFromValue());
        auto subscriptions = getSubscriptions(publication, packet.getName().getPrefix(-2));
        SubscriptionData result = {
          packet.getName(),
          packet.getContent().value_bytes(),
          std::get<0>(publication),
          std::get<2>(publication),
          packet,
        };
        for (const auto& sub : subscriptions) {
          if (sub.isPacketSubscription && m_fetchingMap.at(publication)
                                            .emplace(sub.id, packet.getName()[-1].toSegment())
                                            .second)
            sub.callback(result);
          if (lifetime.expired())
            return;
        }
      });
      fetcher->onComplete.connectSingleShot(
        [this, lifetime, publication, validator] (const ndn::ConstBufferPtr& data) {
          if (lifetime.expired())
            return;
          try {
            Block block(ndn::tlv::Content, data);
            block.parse();
            if (block.elements_size() == 0)
              return failFetch(publication);
            Name name = Data(block.elements().front()).getName().getPrefix(-2);
            Buffer value;
            size_t segment = 0;
            for (const auto& element : block.elements()) {
              Data packet(element);
              const Name expectedName = Name(name).appendVersion(0).appendSegment(segment++);
              const bool hasExpectedName = packet.getName() == expectedName;
              const bool hasExpectedFinalBlock =
                packet.getFinalBlock() == name::Component::fromSegment(block.elements_size() - 1);
              if (!hasExpectedName || !hasExpectedFinalBlock)
                NDN_THROW(std::invalid_argument("inconsistent publication segments"));
              const auto content = packet.getContent().value_bytes();
              value.insert(value.end(), content.begin(), content.end());
            }
            auto subscriptions = getSubscriptions(publication, name);
            cleanUpFetch(publication);
            SubscriptionData result = {
              name,
              value,
              std::get<0>(publication),
              std::get<2>(publication),
              std::nullopt,
            };
            for (const auto& sub : subscriptions) {
              if (!sub.isPacketSubscription)
                sub.callback(result);
              if (lifetime.expired())
                return;
            }
          }
          catch (const std::exception&) {
            if (!lifetime.expired())
              failFetch(publication);
          }
        });
      fetcher->onError.connectSingleShot(
        [this, lifetime, publication, firstData, retries, validationRetries, validator] (
          uint32_t code, const std::string&) {
          if (lifetime.expired())
            return;
          if (code == ndn::SegmentFetcher::INTEREST_TIMEOUT && retries != 0) {
            m_segmentFetchers.erase(publication);
            onSyncData(
              firstData, publication, retries > 0 ? retries - 1 : retries, validationRetries);
          }
          else if (code == ndn::SegmentFetcher::SEGMENT_VALIDATION_FAIL && validationRetries > 0) {
            auto callback = m_opts.onFetchError;
            if (!m_fetchingMap.at(publication).empty() && callback) {
              const auto& [node, epoch, seq] = publication;
              callback(m_svsync.getDataName(node, epoch, seq));
              if (lifetime.expired())
                return;
            }
            m_segmentFetchers.erase(publication);
            m_scheduler.schedule(
              time::milliseconds(m_securityOptions.millisBeforeRetryOnValidationFail),
              [this, lifetime, publication, firstData, retries, validationRetries] {
                if (!lifetime.expired())
                  onSyncData(firstData, publication, retries, validationRetries - 1);
              });
          }
          else {
            failFetch(publication);
          }
        });
      return;
    }

    if (firstData.getName() != expected || innerData.getFinalBlock())
      NDN_THROW(std::invalid_argument("unsegmented outer Data has segmented content"));
    auto deliver = [this, lifetime, publication, innerData] (const Data&) {
      if (lifetime.expired())
        return;
      auto subscriptions = getSubscriptions(publication, innerData.getName());
      cleanUpFetch(publication);
      SubscriptionData result = {
        innerData.getName(),
        innerData.getContent().value_bytes(),
        std::get<0>(publication),
        std::get<2>(publication),
        innerData,
      };
      for (const auto& sub : subscriptions) {
        sub.callback(result);
        if (lifetime.expired())
          return;
      }
    };
    if (m_securityOptions.encapsulatedDataValidator) {
      auto validator = m_securityOptions.encapsulatedDataValidator;
      validator->validate(
        innerData, deliver, [this, lifetime, publication, retries, validationRetries] (auto&&...) {
          if (lifetime.expired())
            return;
          if (validationRetries > 0) {
            m_scheduler.schedule(
              time::milliseconds(m_securityOptions.millisBeforeRetryOnValidationFail),
              [this, lifetime, publication, retries, validationRetries] {
                if (!lifetime.expired())
                  fetchPublication(publication, retries, validationRetries - 1);
              });
          }
          else {
            failFetch(publication);
          }
        });
    }
    else {
      deliver(innerData);
    }
  }
  catch (const std::exception&) {
    if (!lifetime.expired())
      failFetch(publication);
  }
}

void
SVSPubSub::failFetch(const PublicationKey& publication)
{
  auto name = m_svsync.getDataName(
    std::get<0>(publication), std::get<1>(publication), std::get<2>(publication));
  auto callback = m_opts.onFetchError;
  cleanUpFetch(publication);
  if (callback)
    callback(name);
}

void
SVSPubSub::cleanUpFetch(const PublicationKey& publication)
{
  auto fetcher = m_segmentFetchers.find(publication);
  if (fetcher != m_segmentFetchers.end()) {
    fetcher->second->stop();
    m_segmentFetchers.erase(fetcher);
  }
  m_fetchMap.erase(publication);
  m_fetchingMap.erase(publication);
}

Block
SVSPubSub::onGetExtraData(const VersionVector& vv)
{
  std::lock_guard<std::mutex> lock(m_notificationMutex);
  if (m_notificationMappingList.pairs.empty())
    return {};
  const auto node = std::find_if(vv.begin(), vv.end(), [&] (const auto& entry) {
    return entry.first == m_notificationMappingList.nodeId;
  });
  if (node == vv.end())
    return {};
  const auto epoch = node->second.find(m_svsync.getCore().getBootstrapTime());
  if (epoch == node->second.end())
    return {};
  MappingList copy;
  copy.nodeId = m_notificationMappingList.nodeId;
  auto& pending = m_notificationMappingList.pairs;
  for (auto it = pending.begin(); it != pending.end();) {
    if (it->first <= epoch->second) {
      copy.pairs.push_back(*it);
      it = pending.erase(it);
    }
    else {
      ++it;
    }
  }
  if (copy.pairs.empty())
    return {};
  if (pending.empty())
    m_notificationMappingList = MappingList();
  return copy.encode();
}

void
SVSPubSub::onRecvExtraData(const Block& block, const VersionVector& vv)
{
  try {
    MappingList list(block);
    const auto node = std::find_if(
      vv.begin(), vv.end(), [&] (const auto& entry) { return entry.first == list.nodeId; });
    // MappingData has no epoch field. Fall back to queries if the epoch is ambiguous.
    if (node == vv.end() || node->second.size() != 1)
      return;
    const auto& [bootstrapTime, high] = *node->second.begin();
    for (const auto& [seq, mapping] : list.pairs) {
      if (seq <= high)
        m_mappingProvider.insertMapping(list.nodeId, bootstrapTime, seq, mapping);
    }
  } catch (const std::exception&) {
  }
}

} // namespace ndn::svs
