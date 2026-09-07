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

#ifndef NDN_SVS_FETCHER_HPP
#define NDN_SVS_FETCHER_HPP

#include "common.hpp"
#include "security-options.hpp"

#include <ndn-cxx/util/scheduler.hpp>

#include <atomic>
#include <chrono>
#include <queue>

namespace ndn::svs {

class Fetcher
{
public:
  struct Stats
  {
    uint64_t queued = 0;
    uint64_t pending = 0;
    uint16_t window = 0;
    uint64_t dispatched = 0;
    uint64_t data = 0;
    uint64_t nacks = 0;
    uint64_t timeouts = 0;
    uint64_t retries = 0;
  };

  Fetcher(Face& face, const SecurityOptions& securityOptions);

  ~Fetcher();

  void expressInterest(const ndn::Interest& interest,
                       const ndn::DataCallback& afterSatisfied,
                       const ndn::NackCallback& afterNacked,
                       const ndn::TimeoutCallback& afterTimeout,
                       int nRetries = 0,
                       const ndn::security::DataValidationFailureCallback& afterValidationFailed = nullptr);

  void
  setWindowSize(uint16_t windowSize)
  {
    m_windowSize.store(std::max<uint16_t>(1, windowSize),
                       std::memory_order_relaxed);
    processQueue();
  }

  Stats
  getStats() const noexcept
  {
    return {
      m_queuedCount.load(std::memory_order_relaxed),
      m_pendingCount.load(std::memory_order_relaxed),
      m_windowSize.load(std::memory_order_relaxed),
      m_dispatchedCount.load(std::memory_order_relaxed),
      m_dataCount.load(std::memory_order_relaxed),
      m_nackCount.load(std::memory_order_relaxed),
      m_timeoutCount.load(std::memory_order_relaxed),
      m_retryCount.load(std::memory_order_relaxed),
    };
  }

private:
  struct QueuedInterest;

  void expressInterest(const QueuedInterest& qi);

  void onData(const Interest& interest, const Data& data, const QueuedInterest& qi);

  void onNack(const ndn::Interest& interest, const ndn::lp::Nack& nack, const QueuedInterest& qi);

  void onTimeout(const Interest& interest, const QueuedInterest& qi);

  void processQueue();

private:
  Face& m_face;
  ndn::Scheduler m_scheduler;
  const SecurityOptions m_securityOptions;
  std::shared_ptr<std::atomic_bool> m_alive;

  uint64_t m_interestIdCounter = 0;
  std::atomic<uint16_t> m_windowSize{10};
  std::atomic<uint64_t> m_queuedCount{0};
  std::atomic<uint64_t> m_pendingCount{0};
  std::atomic<uint64_t> m_dispatchedCount{0};
  std::atomic<uint64_t> m_dataCount{0};
  std::atomic<uint64_t> m_nackCount{0};
  std::atomic<uint64_t> m_timeoutCount{0};
  std::atomic<uint64_t> m_retryCount{0};

  // Keep a scoped map of all pending interests.
  // This ensures all interests are cancelled when
  // the fetcher is destroyed.
  // The size of this map represents the current window in progress.
  std::map<uint64_t, ScopedPendingInterestHandle> m_pendingInterests;

  // An Interest and its callbacks
  struct QueuedInterest
  {
    uint64_t id;
    Interest interest;
    DataCallback afterSatisfied;
    NackCallback afterNacked;
    TimeoutCallback afterTimeout;
    int nRetries;
    int nRetriesOnValidationFail;
    ndn::security::DataValidationFailureCallback afterValidationFailed;
    std::chrono::steady_clock::time_point queuedAt;
    std::chrono::steady_clock::time_point dispatchedAt;
  };

  // Interests yet to be sent
  std::queue<QueuedInterest> m_interestQueue;
};

} // namespace ndn::svs

#endif // NDN_SVS_FETCHER_HPP
