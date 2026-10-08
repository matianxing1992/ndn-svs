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

#ifndef NDN_SVS_CORE_HPP
#define NDN_SVS_CORE_HPP

#include "common.hpp"
#include "security-options.hpp"
#include "version-vector.hpp"

#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/scheduler.hpp>

#include <mutex>
#include <optional>
#include <set>

namespace ndn::svs {

class MissingDataInfo
{
public:
  /// @brief session name
  NodeID nodeId;
  /// @brief the lowest one of missing sequence numbers
  SeqNo low;
  /// @brief the highest one of missing sequence numbers
  SeqNo high;
  /// @brief ndn::lp::IncomingFaceIdTag
  uint64_t incomingFace;
  /** @brief Bootstrap time identifying the reported node's SVS session, in Unix seconds. */
  BootstrapTime bootstrapTime = 0;
};

/**
 * @brief The callback function to handle state updates
 *
 * The parameter is a set of MissingDataInfo, of which each corresponds to
 * a session that has changed its state.
 */
using UpdateCallback = std::function<void(const std::vector<MissingDataInfo>&)>;

/**
 * @brief Pure SVS
 *
 * Sequence reads and updates may run concurrently with one Face event loop.
 * Configuration, mutable state access, and destruction must be externally
 * serialized. The update callback runs on the Face loop and may destroy the core.
 */
class SVSyncCore : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  /**
   * @brief Constructor
   *
   * @param face The face used to communication
   * @param syncPrefix The prefix of the sync group
   * @param onUpdate The callback function to handle state updates
   * @param securityOptions Signer and validator configuration
   * @param nid ID for the node
   * @param bootstrapTime Persisted session timestamp in Unix seconds; defaults to now
   * Reusing a session also requires restoring its publication sequence and Data store.
   */
  SVSyncCore(ndn::Face& face,
             const Name& syncPrefix,
             const UpdateCallback& onUpdate,
             const SecurityOptions& securityOptions = SecurityOptions::DEFAULT,
             const NodeID& nid = EMPTY_NODE_ID,
             std::optional<BootstrapTime> bootstrapTime = std::nullopt);

  ~SVSyncCore();

  /**
   * @brief Compatibility no-op; synchronization state is not reset.
   *
   * @param isOnInterest Ignored.
   */
  void reset(bool isOnInterest = false);

  /**
   * @brief Get the node ID of the local session.
   *
   * @param prefix prefix of the node
   */
  const NodeID& getNodeId()
  {
    return m_id;
  }

  /**
   * @brief Get the sequence number for @p nid at this core's bootstrap time.
   *
   * An omitted node ID selects the local node. To read a remote session, use
   * getState().get(nid, bootstrapTime) with that session's bootstrap time.
   *
   * @param nid node ID; defaults to the local node
   */
  SeqNo getSeqNo(const NodeID& nid = EMPTY_NODE_ID) const;

  BootstrapTime
  getBootstrapTime() const
  {
    return m_bootstrapTime;
  }

  /**
   * @brief Update the seqNo of the local session
   *
   * The method updates the existing seqNo with the supplied seqNo and NodeID.
   *
   * @param seq The new seqNo.
   * @param nid The NodeID of node to update.
   * @throws std::invalid_argument if seq is zero or decreases within this session.
   */
  void updateSeqNo(const SeqNo& seq, const NodeID& nid = EMPTY_NODE_ID);

  /// @brief Get all the nodeIDs
  std::set<NodeID> getNodeIds() const;

  using GetExtraBlockCallback = std::function<ndn::Block(const VersionVector&)>;
  using RecvExtraBlockCallback = std::function<void(const ndn::Block&, const VersionVector&)>;

  /**
   * @brief Callback to get extra data block for sync interest.
   *
   * Called on the Face's event loop while preparing a State Vector Data packet.
   * The callback may read state but must not publish or destroy this core.
   * It must return one MappingData block or an invalid Block to omit the extension.
   */
  void setGetExtraBlockCallback(const GetExtraBlockCallback& callback)
  {
    m_getExtraBlock = callback;
  }

  /**
   * @brief Callback on receiving MappingData in State Vector Data.
   * Called after configured validation succeeds, before merging the state vector.
   * Not called when no validator is configured.
   */
  void setRecvExtraBlockCallback(const RecvExtraBlockCallback& callback)
  {
    m_recvExtraBlock = callback;
  }

  /// @brief Get current version vector
  VersionVector& getState()
  {
    return m_vv;
  }

  /// @brief Get human-readable representation of version vector
  std::string getStateStr() const
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    return m_vv.toStr();
  }

  NDN_SVS_PUBLIC_WITH_TESTS_ELSE_PRIVATE : void onSyncInterest(const Interest& interest);

  void onSyncInterestValidated(const Data& data, uint64_t incomingFace);

  /**
   * @brief Schedule the first interest if no notification is pending
   */
  void sendInitialInterest();

  /**
   * @brief sendSyncInterest and schedule a new retxSyncInterest event.
   *
   * @param send Send a sync interest immediately
   * @param delay Delay in milliseconds to schedule next interest (-1 for
   * default).
   */
  void retxSyncInterest(bool send, int delay = -1);

  /**
   * @brief Add one sync interest to queue.
   *
   * Called by retxSyncInterest(), or after increasing a sequence
   * number with updateSeqNo()
   */
  void sendSyncInterest();

  struct MergeResult
  {
    /// @brief If the local state vector has newer entries
    bool myVectorNew = false;
    /// @brief If the incoming state vector has newer entries
    bool otherVectorNew = false;
    /** @brief All entries newer than the incoming vector were updated recently. */
    bool recentUpdatesOnly = true;
    /// @brief Newly learned missing information from incoming state vector
    std::vector<MissingDataInfo> missingInfo;
  };

  /**
   * @brief Merge state vector into the current
   * @param vvOther state vector to merge in
   * @details Also adds missing data interests to data interest queue.
   */
  MergeResult mergeStateVector(const VersionVector& vvOther);

  /**
   * @brief Record vector by merging it into m_recordedVv
   * @param vvOther state vector to merge in
   * @returns if recorded successfully
   */
  bool recordVector(const VersionVector& vvOther);

  /**
   * @brief Enter suppression state by initializing m_recordedVv to vvOther.
   * Does nothing if already in suppression state
   *
   * @param vvOther first vector to record
   */
  void enterSuppressionState(const VersionVector& vvOther);

  /// @brief Reference to scheduler
  ndn::Scheduler& getScheduler()
  {
    return m_scheduler;
  }

  /// @brief Get the current time in microseconds with arbitrary reference
  long getCurrentTime() const;

public:
  static inline const NodeID EMPTY_NODE_ID;

private:
  // Communication
  ndn::Face& m_face;
  const Name m_syncPrefix;
  const SecurityOptions m_securityOptions;
  const NodeID m_id;
  const BootstrapTime m_bootstrapTime;
  ndn::ScopedRegisteredPrefixHandle m_syncRegisteredPrefix;

  const UpdateCallback m_onUpdate;

  // State
  VersionVector m_vv;
  mutable std::mutex m_vvMutex;
  // Aggregates incoming vectors while in suppression state
  std::unique_ptr<VersionVector> m_recordedVv = nullptr;

  // Extra block
  GetExtraBlockCallback m_getExtraBlock;
  RecvExtraBlockCallback m_recvExtraBlock;

  // Max suppression time; this value is roughly
  // positively correlated to the network diameter
  time::milliseconds m_maxSuppressionTime;
  // Periodic timer value; can be set to lower
  // for highly lossy networks.
  time::milliseconds m_periodicSyncTime;
  // Fraction of jitter in the periodic timer value.
  // Positively correlated to network diameter.
  double m_periodicSyncJitter;

  // Random Engine
  ndn::random::RandomNumberEngine& m_rng;
  // Milliseconds between sending two sync interests
  std::uniform_int_distribution<> m_retxDist;
  // Milliseconds to send sync interest reply after
  std::uniform_int_distribution<> m_intrReplyDist;

  // Invalidates deferred validation callbacks when the core is destroyed.
  std::shared_ptr<int> m_lifetime = std::make_shared<int>(0);

  ndn::Scheduler m_scheduler;
  scheduler::ScopedEventId m_retxEvent;
  scheduler::ScopedEventId m_registrationFailureEvent;
};

} // namespace ndn::svs

#endif // NDN_SVS_CORE_HPP
