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

#ifndef NDN_SVS_VERSION_VECTOR_HPP
#define NDN_SVS_VERSION_VECTOR_HPP

#include "common.hpp"

#include <map>

namespace ndn::svs {

class VersionVector
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  using const_iterator = std::map<NodeID, std::map<BootstrapTime, SeqNo>>::const_iterator;

  VersionVector() = default;

  /** Decode a version vector from ndn::Block */
  explicit VersionVector(const ndn::Block& encoded);

  /** Encode the version vector to a string */
  ndn::Block encode() const;

  /** Get a human-readable representation */
  std::string toStr() const;

  /** Retain a node even when it has no sequence entries */
  void
  insert(const NodeID& nid)
  {
    if (m_map.try_emplace(nid).second)
      m_lastUpdate[nid] = time::system_clock::now();
  }

  SeqNo
  set(const NodeID& nid, BootstrapTime bootstrapTime, SeqNo seqNo)
  {
    if (seqNo == 0)
      NDN_THROW(std::invalid_argument("SVS sequence number must be positive"));
    m_map[nid][bootstrapTime] = seqNo;
    m_lastUpdate[nid] = time::system_clock::now();
    return seqNo;
  }

  /** Sequence number in the most recent session of this node */
  SeqNo get(const NodeID& nid) const
  {
    auto node = m_map.find(nid);
    return node == m_map.end() || node->second.empty() ? 0 : node->second.rbegin()->second;
  }

  SeqNo
  get(const NodeID& nid, BootstrapTime bootstrapTime) const
  {
    auto node = m_map.find(nid);
    if (node == m_map.end())
      return 0;
    auto entry = node->second.find(bootstrapTime);
    return entry == node->second.end() ? 0 : entry->second;
  }

  time::system_clock::time_point getLastUpdate(const NodeID& nid) const
  {
    auto elem = m_lastUpdate.find(nid);
    return elem == m_lastUpdate.end() ? time::system_clock::time_point::min() : elem->second;
  }

  const_iterator begin() const noexcept
  {
    return m_map.begin();
  }

  const_iterator end() const noexcept
  {
    return m_map.end();
  }

  bool has(const NodeID& nid) const
  {
    return m_map.find(nid) != end();
  }

private:
  std::map<NodeID, std::map<BootstrapTime, SeqNo>> m_map;
  std::map<NodeID, time::system_clock::time_point> m_lastUpdate;
};

} // namespace ndn::svs

#endif // NDN_SVS_VERSION_VECTOR_HPP
