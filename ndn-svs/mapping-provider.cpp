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

#include <string_view>

namespace ndn::svs {

namespace {

Name::Component
makeBootstrapComponent(BootstrapTime bootstrapTime)
{
  return Name::Component("t=" + std::to_string(bootstrapTime));
}

Name::Component
makeSeqComponent(SeqNo seqNo)
{
  return Name::Component("seq=" + std::to_string(seqNo));
}

uint64_t
parseNamedNumber(const Name::Component& component, std::string_view prefix)
{
  const auto value = component.toUri();
  if (value.rfind(prefix, 0) != 0) {
    NDN_THROW(std::invalid_argument("unexpected named number component"));
  }
  return std::stoull(value.substr(prefix.size()));
}

Name
makeMappingKey(const NodeID& nodeId, BootstrapTime bootstrapTime, SeqNo seqNo)
{
  return Name(nodeId).append(makeBootstrapComponent(bootstrapTime)).append(makeSeqComponent(seqNo));
}

} // namespace

MappingList::MappingList() = default;

MappingList::MappingList(const NodeID& nid)
  : nodeId(nid)
{
}

MappingList::MappingList(const Block& block)
{
  block.parse();

  for (auto it = block.elements_begin(); it != block.elements_end(); it++) {
    if (it->type() == ndn::tlv::Name) {
      nodeId = NodeID(*it);
      continue;
    }

    if (it->type() == tlv::MappingEntry) {
      it->parse();

      auto seqNoEntry = it->elements().at(0);
      seqNoEntry.parse();
      if (seqNoEntry.type() != tlv::SeqNoEntry ||
          seqNoEntry.elements().size() < 2 ||
          seqNoEntry.elements().at(0).type() != tlv::BootstrapTime ||
          seqNoEntry.elements().at(1).type() != tlv::SeqNo) {
        NDN_THROW(ndn::tlv::Error("SeqNoEntry", seqNoEntry.type()));
      }
      BootstrapTime bootstrapTime =
        ndn::encoding::readNonNegativeInteger(seqNoEntry.elements().at(0));
      SeqNo seqNo = ndn::encoding::readNonNegativeInteger(seqNoEntry.elements().at(1));
      Name name(it->elements().at(1));

      // Additional blocks
      std::vector<Block> blocks;
      for (auto it2 = it->elements().begin() + 2; it2 != it->elements().end(); it2++)
        blocks.push_back(*it2);

      pairs.push_back({ bootstrapTime, seqNo, std::make_pair(name, blocks) });
      continue;
    }
  }
}

Block
MappingList::encode() const
{
  ndn::encoding::EncodingBuffer enc;
  size_t totalLength = 0;

  for (const auto& entry : pairs) {
    size_t entryLength = 0;

    // Additional blocks
    for (const auto& block : entry.mapping.second)
      entryLength += ndn::encoding::prependBlock(enc, block);

    // Name
    entryLength += ndn::encoding::prependBlock(enc, entry.mapping.first.wireEncode());

    // SeqNoEntry
    size_t seqEntryLength = 0;
    seqEntryLength += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::SeqNo,
                                                                    entry.seqNo);
    seqEntryLength += ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::BootstrapTime,
                                                                    entry.bootstrapTime);
    entryLength += enc.prependVarNumber(seqEntryLength);
    entryLength += enc.prependVarNumber(tlv::SeqNoEntry);
    entryLength += seqEntryLength;

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
  , m_id(id)
  , m_face(face)
  , m_fetcher(face, securityOptions)
  , m_securityOptions(securityOptions)
{
  m_registeredPrefix = m_face.setInterestFilter(Name(m_id).append(m_syncPrefix).append("MAPPING"),
                                                std::bind(&MappingProvider::onMappingQuery, this, _2),
                                                [](auto&&...) {});
}

void
MappingProvider::insertMapping(const NodeID& nodeId, BootstrapTime bootstrapTime,
                               const SeqNo& seqNo, const MappingEntryPair& entry)
{
  std::lock_guard<std::mutex> lock(m_mapMutex);
  m_map[makeMappingKey(nodeId, bootstrapTime, seqNo)] = entry;
}

MappingEntryPair
MappingProvider::getMapping(const NodeID& nodeId, BootstrapTime bootstrapTime,
                            const SeqNo& seqNo)
{
  std::lock_guard<std::mutex> lock(m_mapMutex);
  return m_map.at(makeMappingKey(nodeId, bootstrapTime, seqNo));
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

  for (SeqNo i = query.low; i <= std::max(query.high, query.low); i++) {
    try {
      auto mapping = getMapping(query.nodeId, query.bootstrapTime, i);
      queryResponse.pairs.push_back({query.bootstrapTime, i, mapping});
    } catch (const std::exception&) {
      // TODO: don't give up if not everything is found
      // Instead return whatever we have and let the client request
      // the remaining mappings again
      return;
    }
  }

  // Don't reply if we have nothing
  if (queryResponse.pairs.empty())
    return;

  Data data(interest.getName());
  data.setContent(queryResponse.encode());
  data.setFreshnessPeriod(1_s);
  m_securityOptions.dataSigner->sign(data);
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
  Name queryName = getMappingQueryDataName(info);
  Interest interest(queryName);
  interest.setCanBePrefix(false);
  interest.setMustBeFresh(false);
  interest.setInterestLifetime(2_s);

  auto onDataValidated = [this, onValidated, info](const Data& data) {
    Block block = data.getContent().blockFromValue();
    MappingList list(block);

    // Add all mappings to self
    for (const auto& entry : list.pairs) {
      try {
        getMapping(info.nodeId, entry.bootstrapTime, entry.seqNo);
      } catch (const std::exception&) {
        insertMapping(info.nodeId, entry.bootstrapTime, entry.seqNo, entry.mapping);
      }
    }

    onValidated(list);
  };

  m_fetcher.expressInterest(interest,
                            std::bind(onDataValidated, _2),
                            std::bind(onTimeout, _1), // Nack
                            onTimeout,
                            nRetries,
                            [](auto&&...) {});
}

Name
MappingProvider::getMappingQueryDataName(const MissingDataInfo& info)
{
  return Name(info.nodeId)
    .append(m_syncPrefix)
    .append("MAPPING")
    .append(makeBootstrapComponent(info.bootstrapTime))
    .append(makeSeqComponent(info.low))
    .append(makeSeqComponent(info.high));
}

MissingDataInfo
MappingProvider::parseMappingQueryDataName(const Name& name)
{
  MissingDataInfo info;
  info.bootstrapTime = parseNamedNumber(name.get(-3), "t=");
  info.low = parseNamedNumber(name.get(-2), "seq=");
  info.high = parseNamedNumber(name.get(-1), "seq=");
  info.nodeId = name.getPrefix(-4 - m_syncPrefix.size());
  return info;
}

} // namespace ndn::svs
