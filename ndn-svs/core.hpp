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
#include "sync-protocol.hpp"
#include "version-vector.hpp"

#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/scheduler.hpp>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

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
  /// @brief bootstrap time identifying this node's current SVS session
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
 */
class SVSyncCore : noncopyable
{
public:
  enum class ValidationStatus : uint8_t
  {
    Never,
    Verified,
    StructuralUnverified,
    Rejected,
  };

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
   * @param syncKey Base64 encoded key to sign sync interests
   * @param nid ID for the node
   */
  SVSyncCore(ndn::Face& face,
             const Name& syncPrefix,
             const UpdateCallback& onUpdate,
             const SecurityOptions& securityOptions = SecurityOptions::DEFAULT,
             const NodeID& nid = EMPTY_NODE_ID,
             const SyncProtocolOptions& protocolOptions = {});

  ~SVSyncCore();

  struct SyncProcessingStats
  {
    uint64_t syncJobsSubmitted = 0;
    uint64_t syncJobsCompleted = 0;
    uint64_t syncJobsDropped = 0;
    uint64_t syncJobsStale = 0;
    uint64_t syncWorkerQueueDepth = 0;
    uint64_t syncWorkerProcessingMs = 0;
    uint64_t syncMainThreadPublishMs = 0;
    uint64_t syncInterestSerialHandlerMs = 0;
    uint64_t syncInterestParallelTotalMs = 0;
    uint64_t syncInterestMainThreadBlockingMs = 0;
    uint64_t syncProductionJobsSubmitted = 0;
    uint64_t syncProductionJobsCompleted = 0;
    uint64_t syncProductionJobsDropped = 0;
    uint64_t syncProductionJobsStale = 0;
    uint64_t syncProductionWorkerQueueDepth = 0;
    uint64_t syncProductionWorkerProcessingMs = 0;
    uint64_t syncProductionParallelTotalMs = 0;
  };

  struct SyncRejectionStats
  {
    uint64_t malformedEnvelope = 0;
    uint64_t signaturePolicy = 0;
    uint64_t vectorDecode = 0;
  };

  void
  setParallelSyncProcessing(bool enabled, size_t workerThreads = 1,
                            size_t maxQueueSize = 1024);

  void
  setParallelSyncProduction(bool enabled, size_t workerThreads = 1,
                            size_t maxQueueSize = 1024,
                            bool signInWorker = false,
                            bool buildExtraBlockInWorker = false);

  /**
   * @brief Experimentally coalesce locally triggered sync interests.
   *
   * This only delays sync interests triggered by local publication
   * updateSeqNo() calls. Sync interests needed for reply/suppression and the
   * wire format are unchanged.
   */
  void
  setSyncInterestBatching(bool enabled,
                          time::milliseconds window = 5_ms);

  /**
   * @brief Set the maximum randomized suppression delay for replying to Sync
   * Interests when this node has newer state.
   *
   * This is an implementation timer only; it does not affect the SVS wire
   * format or protocol semantics. Smaller values are useful for small,
   * latency-sensitive groups, while larger values reduce duplicate Sync
   * Interests in large groups.
   */
  void
  setMaxSuppressionTime(time::milliseconds delay);

  /**
   * @brief Set the periodic Sync Interest retransmission interval.
   *
   * This is a diagnostic/testing override. Production and benchmark runs should
   * normally keep the library default because this timer affects piggyback
   * opportunities. Values below 1 ms are clamped to 1 ms.
   */
  void
  setPeriodicSyncTime(time::milliseconds interval,
                      double jitter = 0.1);

  SyncProcessingStats
  getSyncProcessingStats() const;

  SyncRejectionStats
  getSyncRejectionStats() const noexcept
  {
    return {m_malformedEnvelopeRejects.load(std::memory_order_relaxed),
            m_signaturePolicyRejects.load(std::memory_order_relaxed),
            m_vectorDecodeRejects.load(std::memory_order_relaxed)};
  }

  /**
   * @brief Reset the sync tree (and restart synchronization again)
   *
   * @param isOnInterest a flag that tells whether the reset is called by reset
   * interest.
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
   * @brief Get current seqNo of the local session.
   *
   * This method gets the seqNo according to prefix, if prefix is not specified,
   * it returns the seqNo of default user.
   *
   * @param prefix prefix of the node
   */
  SeqNo getSeqNo(const NodeID& nid = EMPTY_NODE_ID) const;

  BootstrapTime getBootstrapTime() const
  {
    return m_bootstrapTime;
  }

  const ResolvedSyncProtocolOptions& getProtocolOptions() const noexcept
  {
    return m_protocolOptions;
  }

  ValidationStatus getLastValidationStatus() const noexcept
  {
    return m_lastValidationStatus.load(std::memory_order_relaxed);
  }

  /**
   * @brief Update the seqNo of the local session
   *
   * The method updates the existing seqNo with the supplied seqNo and NodeID.
   *
   * @param seq The new seqNo.
   * @param nid The NodeID of node to update.
   */
  void updateSeqNo(const SeqNo& seq, const NodeID& nid = EMPTY_NODE_ID);

  void updateSeqNo(const SeqNo& seq, BootstrapTime bootstrapTime, const NodeID& nid);

  /// @brief Get all the nodeIDs
  std::set<NodeID> getNodeIds() const;

  using GetExtraBlockCallback = std::function<ndn::Block(const VersionVector&)>;
  using GetExtraBlocksCallback = std::function<std::vector<ndn::Block>(const VersionVector&)>;
  using RecvExtraBlockCallback = std::function<void(const ndn::Block&, const VersionVector&)>;

  /**
   * @brief Callback to get extra data block for sync interest.
   *
   * The version vector will be locked during the duration of this callback,
   * so it must return FAST!
   */
  void setGetExtraBlockCallback(const GetExtraBlockCallback& callback)
  {
    m_getExtraBlock = callback;
    m_getExtraBlocks = nullptr;
  }

  /**
   * @brief Install a bounded collection producer for trailing extension TLVs.
   *
   * This is the V3 extension API. The singular callback remains available for
   * source compatibility and is adapted to a one-element collection.
   */
  void setGetExtraBlocksCallback(const GetExtraBlocksCallback& callback)
  {
    m_getExtraBlocks = callback;
    m_getExtraBlock = nullptr;
  }

  /**
   * @brief Callback on receiving extra data in a sync interest.
   * Will be called BEFORE the interest is processed.
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
    return m_vv.toStr();
  }

  NDN_SVS_PUBLIC_WITH_TESTS_ELSE_PRIVATE : void onSyncInterest(const Interest& interest);

  void onSyncInterestValidated(const Interest& interest);

  void
  onSyncInterestValidatedSerial(const Interest& interest,
                                bool countSerialStats = true);

  /**
   * @brief Mark the instance as initialized and send the first interest
   */
  void sendInitialInterest();

  /**
   * @brief sendSyncInterest and schedule a new retxSyncInterest event.
   *
   * @param send Send a sync interest immediately
   * @param delay Delay in milliseconds to schedule next interest (0 for
   * default).
   */
  void retxSyncInterest(bool send, unsigned int delay);

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
    /// @brief Newly learned missing information from incoming state vector
    std::vector<MissingDataInfo> missingInfo;
  };

  void
  sendSyncInterestSerial();

  /**
   * @brief Send a Sync Interest for a local publication.
   *
   * Local publications must advertise the newly increased sequence number even
   * if a recently received remote state vector would otherwise suppress a
   * normal retransmission timer.
   */
  void
  sendLocalPublicationSyncInterest();

  /**
   * @brief Merge state vector into the current
   * @param vvOther state vector to merge in
   * @details Also adds missing data interests to data interest queue.
   */
  MergeResult mergeStateVector(const VersionVector& vvOther);

  struct MergeComputationResult
  {
    bool myVectorNew = false;
    bool otherVectorNew = false;
    std::vector<MissingDataInfo> missingData;
    VersionVector mergedVector;
  };

  static MergeComputationResult
  computeMergeStateVector(const VersionVector& localVector,
                          const VersionVector& remoteVector);

  /**
   * @brief Record vector by merging it into m_recordedVv
   * @param vvOther state vector to merge in
   * @returns if recorded successfully
   */
  bool recordVector(const VersionVector& vvOther);

  /**
   * @brief Enter suppression state by setting
   * m_recording to True and initializing m_recordedVv to vvOther.
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
  struct ValidationGate
  {
    std::mutex mutex;
    SVSyncCore* owner = nullptr;
  };

  struct SyncProcessingJob;
  struct SyncProcessingResult;
  struct SyncProductionJob;
  struct SyncProductionResult;
  class SyncWorkerPool;

  void
  processSyncInterestResult(SyncProcessingResult result);

  void
  processSyncProductionResult(SyncProductionResult result);

  void
  signSyncInterest(Interest& interest);

  void
  schedulePublicationSync();

  void
  incrementStat(std::atomic<uint64_t>& counter, uint64_t value = 1) const;

  // Communication
  ndn::Face& m_face;
  const Name m_syncPrefix;
  const Name m_syncInterestPrefix;
  const SecurityOptions m_securityOptions;
  const ResolvedSyncProtocolOptions m_protocolOptions;
  const NodeID m_id;
  const BootstrapTime m_bootstrapTime;
  ndn::ScopedRegisteredPrefixHandle m_syncRegisteredPrefix;

  const UpdateCallback m_onUpdate;

  // State
  VersionVector m_vv;
  mutable std::mutex m_vvMutex;
  uint64_t m_stateGeneration = 0;
  // Aggregates incoming vectors while in suppression state
  std::unique_ptr<VersionVector> m_recordedVv = nullptr;
  mutable std::mutex m_recordedVvMutex;

  // Extra block
  GetExtraBlockCallback m_getExtraBlock;
  GetExtraBlocksCallback m_getExtraBlocks;
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

  // Security
  ndn::KeyChain m_keyChainMem;

  ndn::Scheduler m_scheduler;
  mutable std::mutex m_schedulerMutex;
  scheduler::ScopedEventId m_retxEvent;
  scheduler::ScopedEventId m_packetEvent;
  scheduler::ScopedEventId m_publicationSyncEvent;
  bool m_publicationSyncPending = false;

  // Time at which the next sync interest will be sent
  std::atomic_long m_nextSyncInterest;

  // Prevent sending interests before initialization
  bool m_initialized = false;
  std::atomic<bool> m_syncInterestBatching{false};
  time::milliseconds m_syncInterestBatchWindow = 5_ms;

  std::atomic<bool> m_parallelSyncProcessing{false};
  std::shared_ptr<ValidationGate> m_validationGate = std::make_shared<ValidationGate>();
  std::atomic<ValidationStatus> m_lastValidationStatus{ValidationStatus::Never};
  std::atomic<uint64_t> m_malformedEnvelopeRejects{0};
  std::atomic<uint64_t> m_signaturePolicyRejects{0};
  std::atomic<uint64_t> m_vectorDecodeRejects{0};
  std::shared_ptr<std::atomic<bool>> m_syncProcessingAlive;
  std::unique_ptr<SyncWorkerPool> m_syncWorkerPool;
  std::atomic<uint64_t> m_syncJobsSubmitted{0};
  std::atomic<uint64_t> m_syncJobsCompleted{0};
  std::atomic<uint64_t> m_syncJobsDropped{0};
  std::atomic<uint64_t> m_syncJobsStale{0};
  std::atomic<uint64_t> m_syncWorkerQueueDepth{0};
  std::atomic<uint64_t> m_syncWorkerProcessingMs{0};
  std::atomic<uint64_t> m_syncMainThreadPublishMs{0};
  std::atomic<uint64_t> m_syncInterestSerialHandlerMs{0};
  std::atomic<uint64_t> m_syncInterestParallelTotalMs{0};
  std::atomic<uint64_t> m_syncInterestMainThreadBlockingMs{0};

  std::atomic<bool> m_parallelSyncProduction{false};
  std::atomic<bool> m_parallelSyncProductionSigning{false};
  std::atomic<bool> m_parallelSyncProductionExtraBlock{false};
  std::shared_ptr<std::atomic<bool>> m_syncProductionAlive;
  std::unique_ptr<SyncWorkerPool> m_syncProductionWorkerPool;
  std::mutex m_syncProductionSigningMutex;
  std::atomic<uint64_t> m_syncProductionJobsSubmitted{0};
  std::atomic<uint64_t> m_syncProductionJobsCompleted{0};
  std::atomic<uint64_t> m_syncProductionJobsDropped{0};
  std::atomic<uint64_t> m_syncProductionJobsStale{0};
  std::atomic<uint64_t> m_syncProductionWorkerQueueDepth{0};
  std::atomic<uint64_t> m_syncProductionWorkerProcessingMs{0};
  std::atomic<uint64_t> m_syncProductionParallelTotalMs{0};
};

} // namespace ndn::svs

#endif // NDN_SVS_CORE_HPP
