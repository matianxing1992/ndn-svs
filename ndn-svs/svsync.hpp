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

#ifndef NDN_SVS_SVSYNC_HPP
#define NDN_SVS_SVSYNC_HPP

#include "svsync-base.hpp"

#include <limits>

namespace ndn::svs {

/**
 * @brief SVSync using arbitrary prefix for data delivery
 *
 * The data prefix acts as the node ID in the version vector
 * Sync Interests use <sync-prefix>/v=3/<parameters-digest>
 * Data is produced as <data-prefix>/<sync-prefix>/t=<timestamp>/seq=<seq>
 * The timestamp component encodes bootstrapTime * 1000, with bootstrapTime in Unix seconds.
 */
class SVSync : public SVSyncBase
{
public:
  SVSync(const Name& syncPrefix,
         const Name& nodePrefix,
         ndn::Face& face,
         const UpdateCallback& updateCallback,
         const SecurityOptions& securityOptions = SecurityOptions::DEFAULT,
         std::shared_ptr<DataStore> dataStore = DEFAULT_DATASTORE,
         std::optional<BootstrapTime> bootstrapTime = std::nullopt)
    : SVSyncBase(syncPrefix,
                 Name(nodePrefix).append(syncPrefix),
                 nodePrefix,
                 face,
                 updateCallback,
                 securityOptions,
                 std::move(dataStore),
                 bootstrapTime)
  {
  }

  Name
  getDataName(const NodeID& nid, const BootstrapTime& bootstrapTime, const SeqNo& seqNo) override
  {
    constexpr uint64_t BOOTSTRAP_TIME_NAME_SCALE = 1000;
    if (bootstrapTime > std::numeric_limits<uint64_t>::max() / BOOTSTRAP_TIME_NAME_SCALE)
      NDN_THROW(std::overflow_error("bootstrap time exceeds the timestamp name range"));
    return Name(nid)
      .append(m_syncPrefix)
      .append(name::Component::fromNumber(bootstrapTime * BOOTSTRAP_TIME_NAME_SCALE,
                                          ndn::tlv::TimestampNameComponent))
      .appendSequenceNumber(seqNo);
  }
};

} // namespace ndn::svs

#endif // NDN_SVS_SVSYNC_HPP
