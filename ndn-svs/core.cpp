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

#include "core.hpp"
#include "tlv.hpp"

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <chrono>
#include <cmath>

#ifdef NDN_SVS_COMPRESSION
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filter/lzma.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#endif

namespace ndn::svs {

NDN_LOG_INIT(ndn_svs.SyncTimeline);

namespace {

using SteadyClock = std::chrono::steady_clock;

static uint64_t
elapsedMs(const SteadyClock::time_point& start, const SteadyClock::time_point& end)
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

static uint64_t
elapsedUs(const SteadyClock::time_point& start, const SteadyClock::time_point& end)
{
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

static BootstrapTime
getCurrentBootstrapTime()
{
  return static_cast<BootstrapTime>(
    time::toUnixTimestamp<time::seconds>(time::system_clock::now()).count());
}

static std::string
syncTraceKey(const Interest& interest)
{
  return interest.getName().toUri();
}

} // namespace

struct SVSyncCore::SyncProcessingJob
{
  Interest interest;
  VersionVector localVector;
  uint64_t stateGeneration = 0;
  uint64_t incomingFace = 0;
  SteadyClock::time_point receivedAt;
  SteadyClock::time_point validatedAt;
  std::string traceKey;
};

struct SVSyncCore::SyncProcessingResult
{
  SyncProcessingJob job;
  bool ok = false;
  bool decodeFailed = false;
  VersionVector remoteVector;
  std::vector<Block> extensions;
  MergeComputationResult merge;
  bool myVectorNew = false;
  std::vector<MissingDataInfo> missingData;
  uint64_t parseUs = 0;
  uint64_t decodeUs = 0;
  uint64_t compareUs = 0;
  uint64_t missingUs = 0;
  uint64_t workerUs = 0;
};

struct SVSyncCore::SyncProductionJob
{
  VersionVector localVector;
  std::vector<ndn::Block> extraBlocks;
  uint64_t stateGeneration = 0;
  SteadyClock::time_point submittedAt;
  std::string traceKey;
};

struct SVSyncCore::SyncProductionResult
{
  SyncProductionJob job;
  bool ok = false;
  Interest interest;
  bool signedInWorker = false;
  bool extraBlockBuiltInWorker = false;
  uint64_t encodeUs = 0;
  uint64_t signUs = 0;
  uint64_t workerUs = 0;
};

class SVSyncCore::SyncWorkerPool
{
public:
  explicit
  SyncWorkerPool(size_t workerThreads, size_t maxQueueSize)
    : m_maxQueueSize(std::max<size_t>(1, maxQueueSize))
  {
    workerThreads = std::max<size_t>(1, workerThreads);
    m_workers.reserve(workerThreads);
    for (size_t i = 0; i < workerThreads; ++i) {
      m_workers.emplace_back([this] { run(); });
    }
  }

  ~SyncWorkerPool()
  {
    shutdown();
  }

  bool
  post(std::function<void()> job, size_t& queueDepth)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_stopped || m_queue.size() >= m_maxQueueSize) {
      queueDepth = m_queue.size();
      return false;
    }
    m_queue.push(std::move(job));
    queueDepth = m_queue.size();
    m_cv.notify_one();
    return true;
  }

  void
  shutdown()
  {
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      if (m_stopped) {
        return;
      }
      m_stopped = true;
    }
    m_cv.notify_all();
    for (auto& worker : m_workers) {
      if (worker.joinable()) {
        worker.join();
      }
    }
  }

private:
  void
  run()
  {
    while (true) {
      std::function<void()> job;
      {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this] { return m_stopped || !m_queue.empty(); });
        if (m_stopped && m_queue.empty()) {
          return;
        }
        job = std::move(m_queue.front());
        m_queue.pop();
      }
      job();
    }
  }

private:
  size_t m_maxQueueSize;
  std::vector<std::thread> m_workers;
  std::queue<std::function<void()>> m_queue;
  std::mutex m_mutex;
  std::condition_variable m_cv;
  bool m_stopped = false;
};

SVSyncCore::SVSyncCore(ndn::Face& face,
                       const Name& syncPrefix,
                       const UpdateCallback& onUpdate,
                       const SecurityOptions& securityOptions,
                       const NodeID& nid,
                       const SyncProtocolOptions& protocolOptions)
  : m_face(face)
  , m_syncPrefix(syncPrefix)
  , m_syncInterestPrefix(SyncProtocolCodec::makeSyncName(syncPrefix, protocolOptions.version))
  , m_securityOptions(securityOptions)
  , m_protocolOptions(protocolOptions.resolve())
  , m_id(nid)
  , m_bootstrapTime(m_protocolOptions.version == SvsProtocolVersion::V2 ? 0 :
                    m_protocolOptions.bootstrapTime.value_or(getCurrentBootstrapTime()))
  , m_onUpdate(onUpdate)
  , m_maxSuppressionTime(m_protocolOptions.suppressionPeriod)
  , m_periodicSyncTime(m_protocolOptions.periodicTimeout)
  , m_periodicSyncJitter(m_protocolOptions.periodicJitter)
  , m_rng(ndn::random::getRandomNumberEngine())
  , m_retxDist(m_periodicSyncTime.count() * (1.0 - m_periodicSyncJitter),
               m_periodicSyncTime.count() * (1.0 + m_periodicSyncJitter))
  , m_intrReplyDist(0, m_maxSuppressionTime.count())
  , m_keyChainMem("pib-memory:", "tpm-memory:")
  , m_scheduler(m_face.getIoContext())
{
  m_validationGate->owner = this;
  // Dispatch only the selected wire version locally, but advertise the group
  // prefix so peers that follow the established SVS registration convention
  // can reach this participant through the forwarder.
  m_syncInterestFilter =
    m_face.setInterestFilter(m_syncInterestPrefix,
                             std::bind(&SVSyncCore::onSyncInterest, this, _2));
  m_syncRegisteredPrefix =
    m_face.registerPrefix(m_syncPrefix,
                          std::bind(&SVSyncCore::sendInitialInterest, this),
                          [this] (auto&&...) {
                            NDN_LOG_ERROR("Failed to register sync prefix " << m_syncPrefix);
                          });
}

SVSyncCore::~SVSyncCore()
{
  {
    std::lock_guard<std::mutex> lock(m_validationGate->mutex);
    m_validationGate->owner = nullptr;
  }
  setParallelSyncProduction(false);
  setParallelSyncProcessing(false);
}

void
SVSyncCore::setParallelSyncProcessing(bool enabled, size_t workerThreads,
                                      size_t maxQueueSize)
{
  if (!enabled) {
    m_parallelSyncProcessing = false;
    if (m_syncProcessingAlive) {
      m_syncProcessingAlive->store(false, std::memory_order_relaxed);
    }
    if (m_syncWorkerPool) {
      m_syncWorkerPool->shutdown();
      m_syncWorkerPool.reset();
    }
    return;
  }

  m_syncProcessingAlive = std::make_shared<std::atomic<bool>>(true);
  if (!m_syncWorkerPool) {
    m_syncWorkerPool = std::make_unique<SyncWorkerPool>(workerThreads, maxQueueSize);
  }
  m_parallelSyncProcessing = true;
}

void
SVSyncCore::setParallelSyncProduction(bool enabled, size_t workerThreads,
                                      size_t maxQueueSize,
                                      bool signInWorker,
                                      bool buildExtraBlockInWorker)
{
  if (!enabled) {
    m_parallelSyncProduction = false;
    m_parallelSyncProductionSigning = false;
    m_parallelSyncProductionExtraBlock = false;
    if (m_syncProductionAlive) {
      m_syncProductionAlive->store(false, std::memory_order_relaxed);
    }
    if (m_syncProductionWorkerPool) {
      m_syncProductionWorkerPool->shutdown();
      m_syncProductionWorkerPool.reset();
    }
    return;
  }

  m_syncProductionAlive = std::make_shared<std::atomic<bool>>(true);
  if (!m_syncProductionWorkerPool) {
    m_syncProductionWorkerPool = std::make_unique<SyncWorkerPool>(workerThreads, maxQueueSize);
  }
  m_parallelSyncProductionSigning = signInWorker;
  m_parallelSyncProductionExtraBlock = buildExtraBlockInWorker;
  m_parallelSyncProduction = true;
}

void
SVSyncCore::setSyncInterestBatching(bool enabled, time::milliseconds window)
{
  std::lock_guard<std::mutex> lock(m_schedulerMutex);
  m_syncInterestBatching.store(enabled, std::memory_order_relaxed);
  m_syncInterestBatchWindow = window;
  if (!enabled) {
    m_publicationSyncPending = false;
    m_publicationSyncEvent.cancel();
  }
}

void
SVSyncCore::setMaxSuppressionTime(time::milliseconds delay)
{
  if (delay < 0_ms) {
    delay = 0_ms;
  }

  std::lock_guard<std::mutex> lock(m_schedulerMutex);
  m_maxSuppressionTime = delay;
  m_intrReplyDist = std::uniform_int_distribution<>(0, m_maxSuppressionTime.count());
}

void
SVSyncCore::setPeriodicSyncTime(time::milliseconds interval, double jitter)
{
  if (interval < 1_ms) {
    interval = 1_ms;
  }
  if (jitter < 0.0) {
    jitter = 0.0;
  }
  if (jitter > 1.0) {
    jitter = 1.0;
  }

  std::lock_guard<std::mutex> lock(m_schedulerMutex);
  m_periodicSyncTime = interval;
  m_periodicSyncJitter = jitter;
  const auto lower = static_cast<int>(
    std::max<int64_t>(1, static_cast<int64_t>(
      std::llround(m_periodicSyncTime.count() * (1.0 - m_periodicSyncJitter)))));
  const auto upper = static_cast<int>(
    std::max<int64_t>(lower, static_cast<int64_t>(
      std::llround(m_periodicSyncTime.count() * (1.0 + m_periodicSyncJitter)))));
  m_retxDist = std::uniform_int_distribution<>(lower, upper);
}

SVSyncCore::SyncProcessingStats
SVSyncCore::getSyncProcessingStats() const
{
  SyncProcessingStats stats;
  stats.syncJobsSubmitted = m_syncJobsSubmitted.load();
  stats.syncJobsCompleted = m_syncJobsCompleted.load();
  stats.syncJobsDropped = m_syncJobsDropped.load();
  stats.syncJobsStale = m_syncJobsStale.load();
  stats.syncWorkerQueueDepth = m_syncWorkerQueueDepth.load();
  stats.syncWorkerProcessingMs = m_syncWorkerProcessingMs.load();
  stats.syncMainThreadPublishMs = m_syncMainThreadPublishMs.load();
  stats.syncInterestSerialHandlerMs = m_syncInterestSerialHandlerMs.load();
  stats.syncInterestParallelTotalMs = m_syncInterestParallelTotalMs.load();
  stats.syncInterestMainThreadBlockingMs = m_syncInterestMainThreadBlockingMs.load();
  stats.syncProductionJobsSubmitted = m_syncProductionJobsSubmitted.load();
  stats.syncProductionJobsCompleted = m_syncProductionJobsCompleted.load();
  stats.syncProductionJobsDropped = m_syncProductionJobsDropped.load();
  stats.syncProductionJobsStale = m_syncProductionJobsStale.load();
  stats.syncProductionWorkerQueueDepth = m_syncProductionWorkerQueueDepth.load();
  stats.syncProductionWorkerProcessingMs = m_syncProductionWorkerProcessingMs.load();
  stats.syncProductionParallelTotalMs = m_syncProductionParallelTotalMs.load();
  return stats;
}

void
SVSyncCore::incrementStat(std::atomic<uint64_t>& counter, uint64_t value) const
{
  counter.fetch_add(value, std::memory_order_relaxed);
}

static inline int
suppressionCurve(int constFactor, int value)
{
  // This curve increases the probability that only one or a few
  // nodes pick lower values for timers compared to other nodes.
  // This leads to better suppression results.
  // Increasing the curve factor makes the curve steeper =>
  // better for more nodes, but worse for fewer nodes.

  float c = constFactor;
  float v = value;
  float f = 10.0; // curve factor

  return static_cast<int>(c * (1.0 - std::exp((v - c) / (c / f))));
}

void
SVSyncCore::sendInitialInterest()
{
  // Wait for 100ms before sending the first sync interest
  // This is necessary to give other things time to initialize
  m_scheduler.schedule(100_ms, [this] {
    m_initialized = true;
    retxSyncInterest(true, 0);
  });
}

void
SVSyncCore::onSyncInterest(const Interest& interest)
{
  auto receivedAt = SteadyClock::now();
  auto traceKey = syncTraceKey(interest);
  NDN_LOG_TRACE("event=sync_interest_received key=" << traceKey);
  NDN_LOG_TRACE("event=validation_start key=" << traceKey);

  if (m_protocolOptions.version == SvsProtocolVersion::V3) {
    DecodedSyncEnvelope envelope;
    try {
      envelope = SyncProtocolCodec::decode(interest, m_syncPrefix,
                                           m_protocolOptions.version, false);
    }
    catch (const std::exception& e) {
      m_lastValidationStatus.store(ValidationStatus::Rejected, std::memory_order_relaxed);
      incrementStat(m_malformedEnvelopeRejects);
      NDN_LOG_DEBUG("event=validation_done key=" << traceKey <<
                    " validation=malformed error=" << e.what());
      return;
    }

    if (!envelope.stateVectorData) {
      m_lastValidationStatus.store(ValidationStatus::Rejected, std::memory_order_relaxed);
      NDN_LOG_DEBUG("event=validation_done key=" << traceKey << " validation=missing-data");
      return;
    }
    const auto stateData = *envelope.stateVectorData;
    if (m_securityOptions.validator) {
      auto gate = m_validationGate;
      m_securityOptions.validator->validate(
        stateData,
        [gate, interest, traceKey, receivedAt] (const Data&) {
          std::lock_guard<std::mutex> lock(gate->mutex);
          if (gate->owner == nullptr) {
            return;
          }
          auto& self = *gate->owner;
          self.m_lastValidationStatus.store(ValidationStatus::Verified, std::memory_order_relaxed);
          NDN_LOG_TRACE("event=validation_done key=" << traceKey <<
                        " validation=embedded-data elapsed_us=" <<
                        elapsedUs(receivedAt, SteadyClock::now()));
          self.onSyncInterestValidated(interest);
        },
        [gate, traceKey, receivedAt] (const Data&, const auto& error) {
          std::lock_guard<std::mutex> lock(gate->mutex);
          if (gate->owner == nullptr) {
            return;
          }
          gate->owner->m_lastValidationStatus.store(ValidationStatus::Rejected,
                                                    std::memory_order_relaxed);
          gate->owner->incrementStat(gate->owner->m_signaturePolicyRejects);
          NDN_LOG_DEBUG("event=validation_done key=" << traceKey <<
                        " validation=embedded-data-failed elapsed_us=" <<
                        elapsedUs(receivedAt, SteadyClock::now()) << " error=" << error);
        });
    }
    else {
      m_lastValidationStatus.store(ValidationStatus::StructuralUnverified,
                                   std::memory_order_relaxed);
      NDN_LOG_TRACE("event=validation_done key=" << traceKey <<
                    " validation=structural-unverified elapsed_us=" <<
                    elapsedUs(receivedAt, SteadyClock::now()));
      onSyncInterestValidated(interest);
    }
    return;
  }

  switch (m_securityOptions.interestSigner->signingInfo.getSignerType()) {
    case security::SigningInfo::SIGNER_TYPE_NULL:
      NDN_LOG_TRACE("event=validation_done key=" << traceKey <<
                    " validation=none elapsed_us=" << elapsedUs(receivedAt, SteadyClock::now()));
      onSyncInterestValidated(interest);
      return;

    case security::SigningInfo::SIGNER_TYPE_HMAC:
      if (security::verifySignature(interest,
                                    m_keyChainMem.getTpm(),
                                    m_securityOptions.interestSigner->signingInfo.getSignerName(),
                                    DigestAlgorithm::SHA256)) {
        NDN_LOG_TRACE("event=validation_done key=" << traceKey <<
                      " validation=hmac elapsed_us=" << elapsedUs(receivedAt, SteadyClock::now()));
        onSyncInterestValidated(interest);
      }
      return;

    default:
      if (m_securityOptions.validator) {
        m_securityOptions.validator->validate(interest,
                                              [this, traceKey, receivedAt] (const Interest& validInterest) {
                                                NDN_LOG_TRACE("event=validation_done key=" << traceKey <<
                                                              " validation=validator elapsed_us=" <<
                                                              elapsedUs(receivedAt, SteadyClock::now()));
                                                onSyncInterestValidated(validInterest);
                                              },
                                              [traceKey, receivedAt] (const Interest&, const auto&) {
                                                NDN_LOG_DEBUG("event=validation_done key=" << traceKey <<
                                                              " validation=failed elapsed_us=" <<
                                                              elapsedUs(receivedAt, SteadyClock::now()));
                                              });
      }
      else {
        NDN_LOG_TRACE("event=validation_done key=" << traceKey <<
                      " validation=none elapsed_us=" << elapsedUs(receivedAt, SteadyClock::now()));
        onSyncInterestValidated(interest);
      }
      return;
  }
}

void
SVSyncCore::onSyncInterestValidated(const Interest& interest)
{
  if (!m_parallelSyncProcessing || !m_syncWorkerPool) {
    onSyncInterestValidatedSerial(interest);
    return;
  }

  const auto mainStart = SteadyClock::now();
  const auto traceKey = syncTraceKey(interest);
  SyncProcessingJob job;
  job.interest = interest;
  job.receivedAt = mainStart;
  job.validatedAt = mainStart;
  job.traceKey = traceKey;

  NDN_LOG_TRACE("event=sync_interest_parse_start mode=parallel-main key=" << traceKey);
  {
    auto tag = interest.getTag<ndn::lp::IncomingFaceIdTag>();
    if (tag) {
      job.incomingFace = tag->get();
    }
  }
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    job.localVector = m_vv;
    job.stateGeneration = m_stateGeneration;
  }
  NDN_LOG_TRACE("event=sync_interest_parse_done mode=parallel-main key=" << traceKey <<
                " elapsed_us=" << elapsedUs(mainStart, SteadyClock::now()));

  size_t queueDepth = 0;
  auto* pool = m_syncWorkerPool.get();
  auto alive = m_syncProcessingAlive;
  bool queued = pool->post([this, alive, job = std::move(job)] {
    SyncProcessingResult result;
    result.job = job;
    const auto workerStart = SteadyClock::now();

    try {
      const auto parseStart = SteadyClock::now();
      auto envelope = SyncProtocolCodec::decode(result.job.interest, m_syncPrefix,
                                                m_protocolOptions.version);
      const auto parseDone = SteadyClock::now();
      result.parseUs = elapsedUs(parseStart, parseDone);
      NDN_LOG_TRACE("event=sync_interest_parse_done mode=worker key=" << result.job.traceKey <<
                    " elapsed_us=" << result.parseUs);

      const auto decodeStart = SteadyClock::now();
      NDN_LOG_TRACE("event=state_vector_decode_start mode=worker key=" << result.job.traceKey);
      result.remoteVector = std::move(envelope.stateVector);
      result.extensions = std::move(envelope.extensions);
      const auto decodeDone = SteadyClock::now();
      result.decodeUs = elapsedUs(decodeStart, decodeDone);
      NDN_LOG_TRACE("event=state_vector_decode_done mode=worker key=" << result.job.traceKey <<
                    " elapsed_us=" << result.decodeUs);

      const auto compareStart = SteadyClock::now();
      NDN_LOG_TRACE("event=state_compare_start mode=worker key=" << result.job.traceKey);
      result.merge = computeMergeStateVector(result.job.localVector, result.remoteVector);
      result.myVectorNew = result.merge.myVectorNew;
      const auto compareDone = SteadyClock::now();
      result.compareUs = elapsedUs(compareStart, compareDone);
      NDN_LOG_TRACE("event=state_compare_done mode=worker key=" << result.job.traceKey <<
                    " elapsed_us=" << result.compareUs);

      const auto missingStart = SteadyClock::now();
      NDN_LOG_TRACE("event=missing_data_compute_start mode=worker key=" << result.job.traceKey);
      result.missingData = result.merge.missingData;
      const auto missingDone = SteadyClock::now();
      result.missingUs = elapsedUs(missingStart, missingDone);
      NDN_LOG_TRACE("event=missing_data_compute_done mode=worker key=" << result.job.traceKey <<
                    " elapsed_us=" << result.missingUs);
      result.ok = true;
    }
    catch (const std::exception&) {
      result.decodeFailed = true;
    }

    const auto workerDone = SteadyClock::now();
    result.workerUs = elapsedUs(workerStart, workerDone);
    incrementStat(m_syncWorkerProcessingMs, result.workerUs / 1000);
    NDN_LOG_TRACE("event=sync_worker_processing_ms key=" << result.job.traceKey <<
                  " elapsed_ms=" << (result.workerUs / 1000));

    boost::asio::post(m_face.getIoContext(), [this, alive, result = std::move(result)] () mutable {
      if (!alive || !alive->load(std::memory_order_relaxed)) {
        return;
      }
      processSyncInterestResult(std::move(result));
    });
  }, queueDepth);

  m_syncWorkerQueueDepth.store(queueDepth, std::memory_order_relaxed);

  if (!queued) {
    incrementStat(m_syncJobsDropped);
    NDN_LOG_DEBUG("event=sync_job_queue_full key=" << traceKey <<
                  " queue_depth=" << queueDepth << " action=fallback_serial");
    onSyncInterestValidatedSerial(interest);
    return;
  }

  incrementStat(m_syncJobsSubmitted);
  incrementStat(m_syncInterestMainThreadBlockingMs, elapsedMs(mainStart, SteadyClock::now()));
}

void
SVSyncCore::onSyncInterestValidatedSerial(const Interest& interest, bool countSerialStats)
{
  const auto handlerStart = SteadyClock::now();
  const auto traceKey = syncTraceKey(interest);

  // Get incoming face (this is needed by NLSR)
  uint64_t incomingFace = 0;
  const auto parseStart = SteadyClock::now();
  NDN_LOG_TRACE("event=sync_interest_parse_start mode=serial key=" << traceKey);
  {
    auto tag = interest.getTag<ndn::lp::IncomingFaceIdTag>();
    if (tag) {
      incomingFace = tag->get();
    }
  }
  NDN_LOG_TRACE("event=sync_interest_parse_done mode=serial key=" << traceKey <<
                " elapsed_us=" << elapsedUs(parseStart, SteadyClock::now()));

  VersionVector vvOther;
  std::vector<Block> extensions;
  const auto decodeStart = SteadyClock::now();
  NDN_LOG_TRACE("event=state_vector_decode_start mode=serial key=" << traceKey);
  try {
    auto envelope = SyncProtocolCodec::decode(interest, m_syncPrefix, m_protocolOptions.version);
    vvOther = std::move(envelope.stateVector);
    extensions = std::move(envelope.extensions);
  }
  catch (const std::exception&) {
    incrementStat(m_vectorDecodeRejects);
    NDN_LOG_DEBUG("event=state_vector_decode_failed mode=serial key=" << traceKey);
    return;
  }
  NDN_LOG_TRACE("event=state_vector_decode_done mode=serial key=" << traceKey <<
                " elapsed_us=" << elapsedUs(decodeStart, SteadyClock::now()));

  // Merge state vector
  const auto compareStart = SteadyClock::now();
  NDN_LOG_TRACE("event=state_compare_start mode=serial key=" << traceKey);
  auto result = mergeStateVector(vvOther);
  NDN_LOG_TRACE("event=state_compare_done mode=serial key=" << traceKey <<
                " elapsed_us=" << elapsedUs(compareStart, SteadyClock::now()));

  // The core transition is authoritative and precedes the independent
  // extension transaction in both serial and parallel modes.
  if (!extensions.empty()) {
    try {
      if (m_recvExtraBlocks) {
        m_recvExtraBlocks(extensions, vvOther);
      }
      else if (m_recvExtraBlock) {
        for (const auto& extension : extensions) {
          m_recvExtraBlock(extension, vvOther);
        }
      }
    }
    catch (const std::exception& e) {
      NDN_LOG_DEBUG("event=sync_extension_collection_rejected error=" << e.what());
    }
  }

  const auto missingStart = SteadyClock::now();
  NDN_LOG_TRACE("event=missing_data_compute_start mode=serial key=" << traceKey);
  NDN_LOG_TRACE("event=missing_data_compute_done mode=serial key=" << traceKey <<
                " elapsed_us=" << elapsedUs(missingStart, SteadyClock::now()));

  // Callback if missing data found
  if (!result.missingInfo.empty()) {
    for (auto& e : result.missingInfo)
      e.incomingFace = incomingFace;
    m_onUpdate(result.missingInfo);
  }

  // Try to record; the call will check if in suppression state
  if (recordVector(vvOther))
    return;

  // If incoming state identical/newer to local vector, reset timer
  // If incoming state is older, send sync interest immediately
  if (!result.myVectorNew) {
    retxSyncInterest(false, 0);
  } else {
    enterSuppressionState(vvOther);
    // Check how much time is left on the timer,
    // reset to ~m_intrReplyDist if more than that.
    int delay = m_intrReplyDist(m_rng);

    // Curve the delay for better suppression in large groups
    // TODO: efficient curve depends on number of active nodes
    delay = suppressionCurve(m_maxSuppressionTime.count(), delay);

    if (getCurrentTime() + delay * 1000 < m_nextSyncInterest) {
      retxSyncInterest(false, delay);
    }
  }

  const auto totalMs = elapsedMs(handlerStart, SteadyClock::now());
  NDN_LOG_TRACE("event=total_sync_interest_handler_ms mode=serial key=" << traceKey <<
                " elapsed_ms=" << totalMs);
  NDN_LOG_TRACE("event=main_loop_blocked_ms mode=serial key=" << traceKey <<
                " elapsed_ms=" << totalMs);
  if (countSerialStats) {
    incrementStat(m_syncInterestSerialHandlerMs, totalMs);
    incrementStat(m_syncInterestMainThreadBlockingMs, totalMs);
  }
}

void
SVSyncCore::processSyncInterestResult(SyncProcessingResult result)
{
  const auto mainStart = SteadyClock::now();
  const auto& traceKey = result.job.traceKey;

  if (!result.ok || result.decodeFailed) {
    incrementStat(m_vectorDecodeRejects);
    NDN_LOG_DEBUG("event=sync_parallel_result_decode_failed key=" << traceKey);
    return;
  }

  bool stale = false;
  uint64_t currentGeneration = 0;
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    if (m_stateGeneration != result.job.stateGeneration) {
      stale = true;
      currentGeneration = m_stateGeneration;
    }
    else {
      m_vv = result.merge.mergedVector;
      if (result.merge.otherVectorNew) {
        ++m_stateGeneration;
      }
    }
  }

  if (stale) {
    incrementStat(m_syncJobsStale);
    NDN_LOG_DEBUG("event=sync_job_stale key=" << traceKey <<
                  " captured_generation=" << result.job.stateGeneration <<
                  " current_generation=" << currentGeneration <<
                  " action=fallback_serial");
    // Keep protocol behavior conservative: recompute against current state on
    // the Face/io_context thread instead of applying an old worker snapshot.
    onSyncInterestValidatedSerial(result.job.interest, false);
    return;
  }

  if (!result.extensions.empty()) {
    try {
      if (m_recvExtraBlocks) {
        m_recvExtraBlocks(result.extensions, result.remoteVector);
      }
      else if (m_recvExtraBlock) {
        for (const auto& extension : result.extensions) {
          m_recvExtraBlock(extension, result.remoteVector);
        }
      }
    }
    catch (const std::exception& e) {
      NDN_LOG_DEBUG("event=sync_extension_collection_rejected error=" << e.what());
    }
  }

  if (!result.missingData.empty())
  {
    for (auto& e : result.missingData)
      e.incomingFace = result.job.incomingFace;
    m_onUpdate(result.missingData);
  }

  if (recordVector(result.remoteVector)) {
    incrementStat(m_syncJobsCompleted);
    return;
  }

  if (!result.myVectorNew)
  {
    retxSyncInterest(false, 0);
  }
  else
  {
    enterSuppressionState(result.remoteVector);
    int delay = m_intrReplyDist(m_rng);
    delay = suppressionCurve(m_maxSuppressionTime.count(), delay);

    if (getCurrentTime() + delay * 1000 < m_nextSyncInterest)
    {
      retxSyncInterest(false, delay);
    }
  }

  const auto mainMs = elapsedMs(mainStart, SteadyClock::now());
  const auto totalMs = elapsedMs(result.job.receivedAt, SteadyClock::now());
  incrementStat(m_syncJobsCompleted);
  incrementStat(m_syncInterestMainThreadBlockingMs, mainMs);
  incrementStat(m_syncInterestParallelTotalMs, totalMs);
  NDN_LOG_TRACE("event=sync_interest_parallel_total_ms key=" << traceKey <<
                " elapsed_ms=" << totalMs);
  NDN_LOG_TRACE("event=main_loop_blocked_ms mode=parallel key=" << traceKey <<
                " elapsed_ms=" << mainMs);
}

void
SVSyncCore::retxSyncInterest(bool send, unsigned int delay)
{
  if (send) {
    std::lock_guard<std::mutex> lock(m_recordedVvMutex);

    // Only send interest if in steady state or local vector has newer state
    // than recorded interests
    if (!m_recordedVv || mergeStateVector(*m_recordedVv).myVectorNew)
      sendSyncInterest();
    m_recordedVv = nullptr;
  }

  if (delay == 0)
    delay = m_retxDist(m_rng);

  {
    std::lock_guard<std::mutex> lock(m_schedulerMutex);

    // Store the scheduled time
    m_nextSyncInterest = getCurrentTime() + 1000 * delay;

    m_retxEvent = m_scheduler.schedule(time::milliseconds(delay), [this] { retxSyncInterest(true, 0); });
  }
}

void
SVSyncCore::schedulePublicationSync()
{
  std::lock_guard<std::mutex> lock(m_schedulerMutex);
  if (m_publicationSyncPending) {
    return;
  }

  m_publicationSyncPending = true;
  m_publicationSyncEvent = m_scheduler.schedule(m_syncInterestBatchWindow, [this] {
    {
      std::lock_guard<std::mutex> lock(m_schedulerMutex);
      m_publicationSyncPending = false;
    }
    sendLocalPublicationSyncInterest();
  });
}

void
SVSyncCore::sendLocalPublicationSyncInterest()
{
  try {
    if (m_localPublicationSyncHook) {
      m_localPublicationSyncHook();
    }
    {
      std::lock_guard<std::mutex> lock(m_recordedVvMutex);
      m_recordedVv = nullptr;
    }

    sendSyncInterest();

    unsigned int delay = m_retxDist(m_rng);
    std::lock_guard<std::mutex> lock(m_schedulerMutex);
    m_nextSyncInterest = getCurrentTime() + 1000 * delay;
    m_retxEvent = m_scheduler.schedule(time::milliseconds(delay),
                                       [this] { retxSyncInterest(true, 0); });
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("event=local_publication_sync_send_failed node=" << m_id
                  << " error=" << e.what());
  }
  catch (...) {
    NDN_LOG_ERROR("event=local_publication_sync_send_failed node=" << m_id
                  << " error=unknown");
  }
}

void
SVSyncCore::sendSyncInterest()
{
  if (!m_initialized)
    return;

  if (!m_parallelSyncProduction || !m_syncProductionWorkerPool) {
    sendSyncInterestSerial();
    return;
  }

  const auto mainStart = SteadyClock::now();
  SyncProductionJob job;
  job.submittedAt = mainStart;
  job.traceKey = m_syncPrefix.toUri();

  NDN_LOG_TRACE("event=response_encode_start mode=parallel-main key=" << job.traceKey);
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    job.localVector = m_vv;
    job.stateGeneration = m_stateGeneration;
  }

  if (!m_parallelSyncProductionExtraBlock) {
    if (m_getExtraBlocks) {
      job.extraBlocks = m_getExtraBlocks(job.localVector);
    }
    else if (m_getExtraBlock) {
      job.extraBlocks.push_back(m_getExtraBlock(job.localVector));
    }
  }
  NDN_LOG_TRACE("event=response_encode_snapshot_done mode=parallel-main key=" << job.traceKey <<
                " elapsed_us=" << elapsedUs(mainStart, SteadyClock::now()));

  size_t queueDepth = 0;
  auto* pool = m_syncProductionWorkerPool.get();
  auto alive = m_syncProductionAlive;
  bool queued = pool->post([this, alive, job = std::move(job)] {
    SyncProductionResult result;
    result.job = job;
    const auto workerStart = SteadyClock::now();

    try {
      const auto encodeStart = SteadyClock::now();
      auto extensions = result.job.extraBlocks;
      if (m_parallelSyncProductionExtraBlock && m_getExtraBlocks) {
        extensions = m_getExtraBlocks(result.job.localVector);
        result.extraBlockBuiltInWorker = true;
      }
      else if (m_parallelSyncProductionExtraBlock && m_getExtraBlock) {
        extensions = {m_getExtraBlock(result.job.localVector)};
        result.extraBlockBuiltInWorker = true;
      }

      // A V3 Data signature is covered by the parameters digest. If signer
      // thread use was not explicitly enabled, defer both encoding and signing
      // to the Face thread instead of constructing a hybrid packet.
      if (m_protocolOptions.version == SvsProtocolVersion::V2 ||
          m_parallelSyncProductionSigning) {
        std::lock_guard<std::mutex> signingLock(m_syncProductionSigningMutex);
        result.interest = SyncProtocolCodec::encode(
          m_syncPrefix, result.job.localVector, extensions, m_protocolOptions,
          [this] (Data& data) {
            if (m_securityOptions.dataSigner->signingInfo.getSignerType() ==
                security::SigningInfo::SIGNER_TYPE_NULL) {
              m_keyChainMem.sign(data, security::signingWithSha256());
            }
            else {
              m_securityOptions.dataSigner->sign(data);
            }
          });
        result.encodeUs = elapsedUs(encodeStart, SteadyClock::now());
      }

      if (m_parallelSyncProductionSigning &&
          m_protocolOptions.version == SvsProtocolVersion::V2) {
        const auto signStart = SteadyClock::now();
        NDN_LOG_TRACE("event=response_sign_start mode=parallel-worker key="
                      << result.interest.getName());
        {
          std::lock_guard<std::mutex> signingLock(m_syncProductionSigningMutex);
          signSyncInterest(result.interest);
        }
        result.signUs = elapsedUs(signStart, SteadyClock::now());
        result.signedInWorker = true;
        NDN_LOG_TRACE("event=response_sign_done mode=parallel-worker key="
                      << result.interest.getName() << " elapsed_us=" << result.signUs);
      }

      result.ok = true;
    }
    catch (const std::exception&) {
      result.ok = false;
    }

    result.workerUs = elapsedUs(workerStart, SteadyClock::now());
    incrementStat(m_syncProductionWorkerProcessingMs, result.workerUs / 1000);

    boost::asio::post(m_face.getIoContext(), [this, alive, result = std::move(result)] () mutable {
      if (!alive || !alive->load(std::memory_order_relaxed)) {
        return;
      }
      processSyncProductionResult(std::move(result));
    });
  }, queueDepth);

  m_syncProductionWorkerQueueDepth.store(queueDepth, std::memory_order_relaxed);

  if (!queued) {
    incrementStat(m_syncProductionJobsDropped);
    NDN_LOG_DEBUG("event=sync_production_queue_full key=" << m_syncPrefix <<
                  " queue_depth=" << queueDepth << " action=fallback_serial");
    sendSyncInterestSerial();
    return;
  }

  incrementStat(m_syncProductionJobsSubmitted);
  incrementStat(m_syncInterestMainThreadBlockingMs, elapsedMs(mainStart, SteadyClock::now()));
}

void
SVSyncCore::sendSyncInterestSerial()
{
  if (!m_initialized)
    return;

  const auto publishStart = SteadyClock::now();
  NDN_LOG_TRACE("event=response_encode_start key=" << m_syncPrefix);

  VersionVector stateVector;
  std::vector<Block> extensions;
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    stateVector = m_vv;
    if (m_getExtraBlocks) {
      extensions = m_getExtraBlocks(m_vv);
    }
    else if (m_getExtraBlock) {
      extensions.push_back(m_getExtraBlock(m_vv));
    }
  }

  Interest interest = SyncProtocolCodec::encode(
    m_syncPrefix, stateVector, extensions, m_protocolOptions,
    [this] (Data& data) {
      if (m_securityOptions.dataSigner->signingInfo.getSignerType() ==
          security::SigningInfo::SIGNER_TYPE_NULL) {
        m_keyChainMem.sign(data, security::signingWithSha256());
      }
      else {
        m_securityOptions.dataSigner->sign(data);
      }
    });
  NDN_LOG_TRACE("event=response_encode_done key=" << interest.getName() <<
                " elapsed_us=" << elapsedUs(publishStart, SteadyClock::now()));

  const auto signStart = SteadyClock::now();
  NDN_LOG_TRACE("event=response_sign_start key=" << interest.getName());
  if (m_protocolOptions.version == SvsProtocolVersion::V2) {
    signSyncInterest(interest);
  }
  NDN_LOG_TRACE("event=response_sign_done key=" << interest.getName() <<
                " elapsed_us=" << elapsedUs(signStart, SteadyClock::now()));

  const auto faceStart = SteadyClock::now();
  NDN_LOG_TRACE("event=face_put_start key=" << interest.getName() <<
                " operation=expressInterest");
  m_face.expressInterest(interest, nullptr, nullptr, nullptr);
  NDN_LOG_TRACE("event=face_put_done key=" << interest.getName() <<
                " operation=expressInterest elapsed_us=" << elapsedUs(faceStart, SteadyClock::now()));
  incrementStat(m_syncMainThreadPublishMs, elapsedMs(publishStart, SteadyClock::now()));
}

void
SVSyncCore::processSyncProductionResult(SyncProductionResult result)
{
  const auto mainStart = SteadyClock::now();
  const auto& traceKey = result.job.traceKey;

  if (!result.ok) {
    incrementStat(m_syncProductionJobsDropped);
    NDN_LOG_DEBUG("event=sync_production_failed key=" << traceKey);
    return;
  }

  uint64_t currentGeneration = 0;
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    currentGeneration = m_stateGeneration;
  }

  if (currentGeneration != result.job.stateGeneration && !result.extraBlockBuiltInWorker) {
    incrementStat(m_syncProductionJobsStale);
    NDN_LOG_DEBUG("event=sync_production_stale key=" << traceKey <<
                  " captured_generation=" << result.job.stateGeneration <<
                  " current_generation=" << currentGeneration <<
                  " action=drop");
    return;
  }

  if (currentGeneration != result.job.stateGeneration) {
    incrementStat(m_syncProductionJobsStale);
    NDN_LOG_DEBUG("event=sync_production_stale key=" << traceKey <<
                  " captured_generation=" << result.job.stateGeneration <<
                  " current_generation=" << currentGeneration <<
                  " action=send_extra_block");
  }

  NDN_LOG_TRACE("event=response_encode_done mode=parallel key=" << result.interest.getName() <<
                " elapsed_us=" << result.encodeUs);

  if (!result.interest.hasApplicationParameters()) {
    std::vector<Block> extensions;
    extensions = result.job.extraBlocks;
    const auto encodeStart = SteadyClock::now();
    result.interest = SyncProtocolCodec::encode(
      m_syncPrefix, result.job.localVector, extensions, m_protocolOptions,
      [this] (Data& data) {
        if (m_securityOptions.dataSigner->signingInfo.getSignerType() ==
            security::SigningInfo::SIGNER_TYPE_NULL) {
          m_keyChainMem.sign(data, security::signingWithSha256());
        }
        else {
          m_securityOptions.dataSigner->sign(data);
        }
      });
    NDN_LOG_TRACE("event=response_encode_done mode=parallel-main key="
                  << result.interest.getName() << " elapsed_us="
                  << elapsedUs(encodeStart, SteadyClock::now()));
  }

  if (!result.signedInWorker && m_protocolOptions.version == SvsProtocolVersion::V2) {
    const auto signStart = SteadyClock::now();
    NDN_LOG_TRACE("event=response_sign_start mode=parallel key=" << result.interest.getName());
    signSyncInterest(result.interest);
    NDN_LOG_TRACE("event=response_sign_done mode=parallel key=" << result.interest.getName() <<
                  " elapsed_us=" << elapsedUs(signStart, SteadyClock::now()));
  }
  else if (result.signedInWorker) {
    NDN_LOG_TRACE("event=response_sign_done mode=parallel-worker-result key="
                  << result.interest.getName() << " elapsed_us=" << result.signUs);
  }

  const auto faceStart = SteadyClock::now();
  NDN_LOG_TRACE("event=face_put_start mode=parallel key=" << result.interest.getName() <<
                " operation=expressInterest");
  m_face.expressInterest(result.interest, nullptr, nullptr, nullptr);
  NDN_LOG_TRACE("event=face_put_done mode=parallel key=" << result.interest.getName() <<
                " operation=expressInterest elapsed_us=" << elapsedUs(faceStart, SteadyClock::now()));

  const auto mainMs = elapsedMs(mainStart, SteadyClock::now());
  const auto totalMs = elapsedMs(result.job.submittedAt, SteadyClock::now());
  incrementStat(m_syncProductionJobsCompleted);
  incrementStat(m_syncProductionParallelTotalMs, totalMs);
  incrementStat(m_syncMainThreadPublishMs, mainMs);
  incrementStat(m_syncInterestMainThreadBlockingMs, mainMs);
}

void
SVSyncCore::signSyncInterest(Interest& interest)
{
  switch (m_securityOptions.interestSigner->signingInfo.getSignerType()) {
    case security::SigningInfo::SIGNER_TYPE_NULL:
      break;

    case security::SigningInfo::SIGNER_TYPE_HMAC:
      m_keyChainMem.sign(interest, m_securityOptions.interestSigner->signingInfo);
      break;

    default:
      m_securityOptions.interestSigner->sign(interest);
      break;
  }
}

SVSyncCore::MergeResult
SVSyncCore::mergeStateVector(const VersionVector& vvOther)
{
  std::lock_guard<std::mutex> lock(m_vvMutex);

  auto result = computeMergeStateVector(m_vv, vvOther);
  m_vv = result.mergedVector;
  if (result.otherVectorNew) {
    ++m_stateGeneration;
  }

  return {result.myVectorNew, result.otherVectorNew, result.missingData};
}

SVSyncCore::MergeComputationResult
SVSyncCore::computeMergeStateVector(const VersionVector& localVector,
                                    const VersionVector& remoteVector)
{
  MergeComputationResult result;
  result.mergedVector = localVector;

  for (const auto& [nidOther, seqEntries] : remoteVector.getAllEntries()) {
    for (const auto& [bootstrapTime, seqOther] : seqEntries) {
      SeqNo seqCurrent = result.mergedVector.get(nidOther, bootstrapTime);

      if (seqCurrent < seqOther) {
        result.otherVectorNew = true;
        result.missingData.push_back({nidOther, seqCurrent + 1, seqOther, 0, bootstrapTime});
        result.mergedVector.set(nidOther, bootstrapTime, seqOther);
      }
    }
  }

  for (const auto& [nid, seqEntries] : result.mergedVector.getAllEntries()) {
    for (const auto& [bootstrapTime, seq] : seqEntries) {
      SeqNo seqOther = remoteVector.get(nid, bootstrapTime);

      if (seqOther < seq) {
        result.myVectorNew = true;
        break;
      }
    }
    if (result.myVectorNew) {
      break;
    }
  }

  return result;
}

void
SVSyncCore::reset(bool isOnInterest)
{
}

SeqNo
SVSyncCore::getSeqNo(const NodeID& nid) const
{
  std::lock_guard<std::mutex> lock(m_vvMutex);
  NodeID t_nid = (nid == EMPTY_NODE_ID) ? m_id : nid;
  if (t_nid == m_id) {
    return m_vv.get(t_nid, m_bootstrapTime);
  }
  return m_vv.get(t_nid);
}

void
SVSyncCore::updateSeqNo(const SeqNo& seq, const NodeID& nid)
{
  NodeID t_nid = (nid == EMPTY_NODE_ID) ? m_id : nid;
  updateSeqNo(seq, m_bootstrapTime, t_nid);
}

void
SVSyncCore::updateSeqNo(const SeqNo& seq, BootstrapTime bootstrapTime, const NodeID& nid)
{
  NodeID t_nid = (nid == EMPTY_NODE_ID) ? m_id : nid;

  SeqNo prev;
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    prev = m_vv.get(t_nid, bootstrapTime);
    m_vv.set(t_nid, bootstrapTime, seq);
    if (seq > prev) {
      ++m_stateGeneration;
    }
  }

  if (seq > prev)
  {
    try {
      if (m_syncInterestBatching.load(std::memory_order_relaxed)) {
        schedulePublicationSync();
      }
      else {
        sendLocalPublicationSyncInterest();
      }
    }
    catch (const std::exception& e) {
      NDN_LOG_ERROR("event=local_publication_sync_send_failed node=" << t_nid
                    << " seq=" << seq << " error=" << e.what());
    }
    catch (...) {
      NDN_LOG_ERROR("event=local_publication_sync_send_failed node=" << t_nid
                    << " seq=" << seq << " error=unknown");
    }
  }
}

std::set<NodeID>
SVSyncCore::getNodeIds() const
{
  std::lock_guard<std::mutex> lock(m_vvMutex);
  std::set<NodeID> sessionNames;
  for (const auto& nid : m_vv) {
    sessionNames.insert(nid.first);
  }
  return sessionNames;
}

long
SVSyncCore::getCurrentTime() const
{
  return std::chrono::duration_cast<std::chrono::microseconds>(
           std::chrono::steady_clock::now().time_since_epoch())
    .count();
}

bool
SVSyncCore::recordVector(const VersionVector& vvOther)
{
  std::lock_guard<std::mutex> lock(m_recordedVvMutex);

  if (!m_recordedVv)
    return false;

  std::lock_guard<std::mutex> lock1(m_vvMutex);

  for (const auto& [nidOther, seqEntries] : vvOther.getAllEntries()) {
    for (const auto& [bootstrapTime, seqOther] : seqEntries) {
      SeqNo seqCurrent = m_recordedVv->get(nidOther, bootstrapTime);

      if (seqCurrent < seqOther) {
        m_recordedVv->set(nidOther, bootstrapTime, seqOther);
      }
    }
  }

  return true;
}

void
SVSyncCore::enterSuppressionState(const VersionVector& vvOther)
{
  std::lock_guard<std::mutex> lock(m_recordedVvMutex);

  if (!m_recordedVv)
    m_recordedVv = std::make_unique<VersionVector>(vvOther);
}

} // namespace ndn::svs
