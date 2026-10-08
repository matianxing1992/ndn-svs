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

#include "mapping-provider.hpp"
#include "tlv.hpp"

#include <algorithm>
#include <limits>
#include <set>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

namespace ndn::svs {

static constexpr uint64_t BOOTSTRAP_TIME_NAME_SCALE = 1000;

static inline Name
makeMappingKey(const NodeID& nodeId, BootstrapTime bootstrapTime, SeqNo seqNo)
{
  return Name(nodeId)
    .append(name::Component::fromNumber(bootstrapTime, ndn::tlv::TimestampNameComponent))
    .appendSequenceNumber(seqNo);
}

MappingList::MappingList() = default;

MappingList::MappingList(const NodeID& nid)
  : nodeId(nid)
{
}

MappingList::MappingList(const Block& block)
{
  if (block.type() != tlv::MappingData)
    NDN_THROW(ndn::tlv::Error("expected MappingData"));
  block.parse();
  const bool hasNodeName =
    !block.elements().empty() && block.elements().front().type() == ndn::tlv::Name;
  if (!hasNodeName)
    NDN_THROW(ndn::tlv::Error("MappingData must begin with Name"));
  nodeId = NodeID(block.elements().front());

  for (auto it = block.elements_begin() + 1; it != block.elements_end(); it++) {
    if (it->type() == tlv::MappingEntry) {
      it->parse();

      const auto& elements = it->elements();
      const bool hasValidEntry = elements.size() >= 2 &&
                                 elements.at(0).type() == tlv::MappingSeqNo &&
                                 elements.at(1).type() == ndn::tlv::Name;
      if (!hasValidEntry) {
        NDN_THROW(ndn::tlv::Error("MappingEntry must begin with SeqNo and Name"));
      }
      SeqNo seqNo = ndn::encoding::readNonNegativeInteger(it->elements().at(0));
      if (seqNo == 0)
        NDN_THROW(ndn::tlv::Error("MappingEntry sequence number must be positive"));
      Name name(it->elements().at(1));

      // Additional blocks
      std::vector<Block> blocks;
      for (auto it2 = it->elements().begin() + 2; it2 != it->elements().end(); it2++)
        blocks.push_back(*it2);

      pairs.push_back({ seqNo, std::make_pair(name, blocks) });
      continue;
    }
    NDN_THROW(ndn::tlv::Error("unexpected MappingData element"));
  }
}

Block
MappingList::encode() const
{
  ndn::encoding::EncodingBuffer enc;
  size_t totalLength = 0;

  for (const auto& [seq, mapping] : pairs) {
    size_t entryLength = 0;

    // Additional blocks
    for (auto it = mapping.second.rbegin(); it != mapping.second.rend(); ++it)
      entryLength += ndn::encoding::prependBlock(enc, *it);

    // Name
    entryLength += ndn::encoding::prependBlock(enc, mapping.first.wireEncode());

    // SeqNo
    entryLength += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::MappingSeqNo, seq);

    totalLength += enc.prependVarNumber(entryLength);
    totalLength += enc.prependVarNumber(tlv::MappingEntry);
    totalLength += entryLength;
  }

  totalLength += ndn::encoding::prependBlock(enc, nodeId.wireEncode());

  enc.prependVarNumber(totalLength);
  enc.prependVarNumber(tlv::MappingData);
  return enc.block();
}

MappingProvider::MappingProvider(const Name& syncPrefix,
                                 const NodeID& id,
                                 ndn::Face& face,
                                 const SecurityOptions& securityOptions)
  : m_syncPrefix(syncPrefix)
  , m_face(face)
  , m_fetcher(face,
              [&] {
                auto options = securityOptions;
                if (options.mappingValidator)
                  options.validator = options.mappingValidator;
                return options;
              }())
  , m_securityOptions(securityOptions)
{
  addLocalNode(id);
}

void
MappingProvider::addLocalNode(const NodeID& id)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_interestFilters.emplace(id, ndn::ScopedRegisteredPrefixHandle()).second)
    return;
  boost::asio::post(m_face.getIoContext(), [this, id, lifetime = std::weak_ptr<int>(m_lifetime)] {
    if (lifetime.expired())
      return;
    std::lock_guard<std::mutex> lock(m_mutex);
    auto registration = std::make_shared<ndn::RegisteredPrefixHandle>();
    *registration = m_face.setInterestFilter(
      Name(id).append(m_syncPrefix),
      [this, lifetime] (const auto&, const Interest& interest) {
        if (!lifetime.expired())
          onMappingQuery(interest);
      },
      [lifetime, registration] (auto&&...) {
        if (lifetime.expired())
          registration->unregister();
      },
      [] (auto&&...) {});
    m_interestFilters.at(id) = *registration;
  });
}

void
MappingProvider::insertMapping(const NodeID& nodeId,
                               BootstrapTime bootstrapTime,
                               const SeqNo& seqNo,
                               const MappingEntryPair& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  const auto key = makeMappingKey(nodeId, bootstrapTime, seqNo);
  auto packet = m_localMappingPackets.find(key);
  if (packet != m_localMappingPackets.end() &&
      MappingList(packet->second->getContent().blockFromValue()).pairs.front().second != entry) {
    m_localMappingPackets.erase(packet);
    packet = m_localMappingPackets.end();
  }
  if (packet == m_localMappingPackets.end() && m_interestFilters.count(nodeId) != 0)
    validateMappingSize(nodeId, bootstrapTime, seqNo, entry);
  m_map[key] = entry;
}

MappingEntryPair
MappingProvider::getMapping(const NodeID& nodeId, BootstrapTime bootstrapTime, const SeqNo& seqNo)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_map.at(makeMappingKey(nodeId, bootstrapTime, seqNo));
}

void
MappingProvider::validateMappingSize(const NodeID& id,
                                     BootstrapTime bootstrapTime,
                                     SeqNo seq,
                                     const MappingEntryPair& entry)
{
  if (seq == 0)
    NDN_THROW(std::invalid_argument("mapping sequence number must be positive"));
  MappingList list(id);
  list.pairs.emplace_back(seq, entry);
  Data data(getMappingQueryDataName({id, seq, seq, 0, bootstrapTime}));
  data.setContent(list.encode());
  data.setFreshnessPeriod(1_s);
  const auto& signer = m_securityOptions.mappingSigner ? m_securityOptions.mappingSigner
                                                       : m_securityOptions.dataSigner;
  signer->sign(data);
  if (data.wireEncode().size() > ndn::MAX_NDN_PACKET_SIZE)
    NDN_THROW(std::length_error("publication mapping exceeds the packet size limit"));
  m_localMappingPackets[makeMappingKey(id, bootstrapTime, seq)] =
    std::make_shared<Data>(std::move(data));
}

void
MappingProvider::onMappingQuery(const Interest& interest)
{
  MissingDataInfo query;
  try {
    query = parseMappingQueryDataName(interest.getName());
  }
  catch (const std::exception&) {
    return;
  }

  MappingList queryResponse(query.nodeId);

  for (SeqNo i = query.low;; ++i) {
    try {
      auto mapping = getMapping(query.nodeId, query.bootstrapTime, i);
      queryResponse.pairs.emplace_back(i, mapping);
    } catch (const std::exception&) {
      return;
    }
    if (i == query.high)
      break;
  }

  // Don't reply if we have nothing
  if (queryResponse.pairs.empty())
    return;

  if (query.low == query.high) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto packet =
      m_localMappingPackets.find(makeMappingKey(query.nodeId, query.bootstrapTime, query.low));
    if (packet != m_localMappingPackets.end()) {
      m_face.put(*packet->second);
      return;
    }
  }

  Data data(interest.getName());
  data.setContent(queryResponse.encode());
  data.setFreshnessPeriod(1_s);
  const auto& signer = m_securityOptions.mappingSigner ? m_securityOptions.mappingSigner
                                                       : m_securityOptions.dataSigner;
  signer->sign(data);
  if (data.wireEncode().size() > ndn::MAX_NDN_PACKET_SIZE)
    return;
  m_face.put(data);
}

void
MappingProvider::fetchNameMapping(const MissingDataInfo& info,
                                  const MappingListCallback& onValidated,
                                  int nRetries)
{
  TimeoutCallback onTimeout = [](auto&&...) {};
  return fetchNameMapping(info, onValidated, onTimeout, nRetries);
}

void
MappingProvider::fetchNameMapping(const MissingDataInfo& info,
                                  const MappingListCallback& onValidated,
                                  const TimeoutCallback& onTimeout,
                                  int nRetries)
{
  if (info.low == 0 || info.high < info.low)
    NDN_THROW(std::invalid_argument("mapping query must have a positive closed sequence range"));
  Name queryName = getMappingQueryDataName(info);
  Interest interest(queryName);
  interest.setCanBePrefix(false);
  interest.setMustBeFresh(false);
  interest.setInterestLifetime(2_s);

  auto onFailure = [this, onValidated, onTimeout, interest, info, nRetries] (const Interest&) {
    if (info.low == info.high) {
      onTimeout(interest);
      return;
    }
    // Retry an unanswered or incomplete range as smaller exact queries.
    auto left = info;
    auto right = info;
    left.high = info.low + (info.high - info.low) / 2;
    right.low = left.high + 1;
    fetchNameMapping(left, onValidated, onTimeout, nRetries);
    fetchNameMapping(right, onValidated, onTimeout, nRetries);
  };

  auto onDataValidated = [this, onValidated, onFailure, interest, info] (const Data& data) {
    MappingList list;
    try {
      Block block = data.getContent().blockFromValue();
      list = MappingList(block);
      std::set<SeqNo> sequences;
      if (list.nodeId != info.nodeId)
        NDN_THROW(ndn::tlv::Error("MappingData does not match the requested node and range"));
      const bool hasInvalidEntries =
        std::any_of(list.pairs.begin(), list.pairs.end(), [&] (const auto& entry) {
          const bool isOutOfRange = entry.first < info.low || entry.first > info.high;
          return isOutOfRange || !sequences.insert(entry.first).second;
        });
      const bool hasCompleteRange =
        !hasInvalidEntries && !sequences.empty() && info.high - info.low == sequences.size() - 1;
      if (!hasCompleteRange)
        NDN_THROW(ndn::tlv::Error("MappingData does not match the requested node and range"));

      // Add all mappings to self
      for (const auto& [seq, mapping] : list.pairs) {
        try {
          getMapping(info.nodeId, info.bootstrapTime, seq);
        }
        catch (const std::exception&) {
          insertMapping(info.nodeId, info.bootstrapTime, seq, mapping);
        }
      }
    }
    catch (const ndn::tlv::Error&) {
      onFailure(interest);
      return;
    }
    onValidated(list);
  };

  m_fetcher.expressInterest(interest,
                            std::bind(onDataValidated, _2),
                            std::bind(onFailure, _1), // Nack
                            onFailure,
                            info.low == info.high ? nRetries : 0,
                            [onTimeout, interest] (auto&&...) { onTimeout(interest); });
}

Name
MappingProvider::getMappingQueryDataName(const MissingDataInfo& info)
{
  if (info.bootstrapTime > std::numeric_limits<uint64_t>::max() / BOOTSTRAP_TIME_NAME_SCALE)
    NDN_THROW(std::overflow_error("bootstrap time exceeds the timestamp name range"));
  Name name = Name(info.nodeId).append(m_syncPrefix);
  return name
    .append(ndn::name::Component::fromNumber(info.bootstrapTime * BOOTSTRAP_TIME_NAME_SCALE,
                                             ndn::tlv::TimestampNameComponent))
    .append("MAPPING")
    .appendSequenceNumber(info.low)
    .appendSequenceNumber(info.high);
}

MissingDataInfo
MappingProvider::parseMappingQueryDataName(const Name& name)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  MissingDataInfo info;
  if (name.size() < m_syncPrefix.size() + 4)
    NDN_THROW(std::invalid_argument("invalid SVS-PS Mapping query name"));
  const NodeID node = name.getPrefix(-4 - m_syncPrefix.size());
  const Name expectedPrefix = Name(node).append(m_syncPrefix);
  const bool hasValidPrefix =
    m_interestFilters.count(node) != 0 && name.getPrefix(expectedPrefix.size()) == expectedPrefix;
  const bool hasValidSuffix = hasValidPrefix && name.get(-3) == Name::Component("MAPPING") &&
                              name.get(-4).isTimestamp() && name.get(-2).isSequenceNumber() &&
                              name.get(-1).isSequenceNumber();
  if (!hasValidPrefix || !hasValidSuffix) {
    NDN_THROW(std::invalid_argument("invalid SVS-PS Mapping query name"));
  }
  const auto timestamp = name.get(-4).toNumber();
  if (timestamp % BOOTSTRAP_TIME_NAME_SCALE != 0)
    NDN_THROW(
      std::invalid_argument("mapping timestamp does not encode an integral bootstrap time"));
  info.bootstrapTime = timestamp / BOOTSTRAP_TIME_NAME_SCALE;
  info.low = name.get(-2).toSequenceNumber();
  info.high = name.get(-1).toSequenceNumber();
  if (info.low == 0 || info.high < info.low)
    NDN_THROW(std::invalid_argument("invalid SVS-PS Mapping query range"));
  info.nodeId = node;
  return info;
}

} // namespace ndn::svs
