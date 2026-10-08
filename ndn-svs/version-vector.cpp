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

#include "version-vector.hpp"
#include "tlv.hpp"

namespace ndn::svs {

static inline bool
isBootstrapTimeTooFarInFuture(BootstrapTime bootstrapTime)
{
  const auto now = static_cast<BootstrapTime>(
    time::toUnixTimestamp<time::seconds>(time::system_clock::now()).count());
  const auto futureTolerance = time::duration_cast<time::seconds>(time::hours(24)).count();
  return bootstrapTime > now + futureTolerance;
}

VersionVector::VersionVector(const ndn::Block& block)
{
  if (block.type() != tlv::StateVector)
    NDN_THROW(ndn::tlv::Error("StateVector", block.type()));

  block.parse();

  for (auto it = block.elements_begin(); it < block.elements_end(); it++) {
    if (it->type() != tlv::StateVectorEntry)
      NDN_THROW(ndn::tlv::Error("StateVectorEntry", it->type()));

    it->parse();
    const auto& elements = it->elements();
    const bool hasNodeName = !elements.empty() && elements.front().type() == ndn::tlv::Name;
    if (!hasNodeName) {
      NDN_THROW(ndn::tlv::Error("Name", elements.empty() ? 0 : elements.front().type()));
    }

    NodeID nodeId(elements.front());
    insert(nodeId);
    for (auto seqIt = elements.begin() + 1; seqIt != elements.end(); ++seqIt) {
      if (seqIt->type() == tlv::SeqNoEntry) {
        seqIt->parse();
        const auto& seqElements = seqIt->elements();
        const bool hasValidSequence = seqElements.size() == 2 &&
                                      seqElements.at(0).type() == tlv::BootstrapTime &&
                                      seqElements.at(1).type() == tlv::SeqNo;
        if (!hasValidSequence) {
          NDN_THROW(ndn::tlv::Error("SeqNoEntry", seqIt->type()));
        }
        BootstrapTime bootstrapTime =
          ndn::encoding::readNonNegativeInteger(seqIt->elements().at(0));
        if (isBootstrapTimeTooFarInFuture(bootstrapTime)) {
          NDN_THROW(Error("State vector bootstrap time is too far in the future"));
        }
        SeqNo seqNo = ndn::encoding::readNonNegativeInteger(seqIt->elements().at(1));
        if (seqNo == 0) {
          NDN_THROW(Error("State vector sequence number must be positive"));
        }
        set(nodeId, bootstrapTime, seqNo);
        continue;
      }

      NDN_THROW(ndn::tlv::Error("SeqNoEntry", seqIt->type()));
    }
  }
}

ndn::Block
VersionVector::encode() const
{
  ndn::encoding::EncodingBuffer enc;
  size_t totalLength = 0;

  for (auto it = m_map.rbegin(); it != m_map.rend(); it++) {
    size_t entryLength = 0;

    for (auto seqIt = it->second.rbegin(); seqIt != it->second.rend(); ++seqIt) {
      size_t seqEntryLength = 0;
      seqEntryLength +=
        ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::SeqNo, seqIt->second);
      seqEntryLength +=
        ndn::encoding::prependNonNegativeIntegerBlock(enc, tlv::BootstrapTime, seqIt->first);
      entryLength += enc.prependVarNumber(seqEntryLength);
      entryLength += enc.prependVarNumber(tlv::SeqNoEntry);
      entryLength += seqEntryLength;
    }

    // NodeID (Name)
    entryLength += ndn::encoding::prependBlock(enc, it->first.wireEncode());

    totalLength += enc.prependVarNumber(entryLength);
    totalLength += enc.prependVarNumber(tlv::StateVectorEntry);
    totalLength += entryLength;
  }

  enc.prependVarNumber(totalLength);
  enc.prependVarNumber(tlv::StateVector);
  return enc.block();
}

std::string
VersionVector::toStr() const
{
  std::ostringstream stream;
  for (const auto& elem : m_map) {
    stream << elem.first << ":";
    for (const auto& seqEntry : elem.second) {
      stream << "[" << seqEntry.first << "," << seqEntry.second << "]";
    }
    stream << " ";
  }
  return stream.str();
}

} // namespace ndn::svs
