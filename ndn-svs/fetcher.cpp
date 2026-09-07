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

#include "fetcher.hpp"
#include "security-options.hpp"

#include <ndn-cxx/util/logger.hpp>

namespace ndn::svs {

NDN_LOG_INIT(ndn_svs.Fetcher);

namespace {

using SteadyClock = std::chrono::steady_clock;

uint64_t
elapsedUs(const SteadyClock::time_point& begin, const SteadyClock::time_point& end)
{
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count());
}

uint64_t
monotonicNs(const SteadyClock::time_point& value)
{
  return static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::nanoseconds>(value.time_since_epoch()).count());
}

} // namespace

Fetcher::Fetcher(Face& face, const SecurityOptions& securityOptions)
  : m_face(face)
  , m_scheduler(face.getIoContext())
  , m_securityOptions(securityOptions)
  , m_alive(std::make_shared<std::atomic_bool>(true))
{
}

Fetcher::~Fetcher()
{
  m_alive->store(false, std::memory_order_relaxed);
  m_scheduler.cancelAllEvents();
  m_pendingInterests.clear();
  m_pendingCount.store(0, std::memory_order_relaxed);
  while (!m_interestQueue.empty()) {
    m_interestQueue.pop();
  }
  m_queuedCount.store(0, std::memory_order_relaxed);
}

void
Fetcher::expressInterest(const ndn::Interest& interest,
                         const ndn::DataCallback& afterSatisfied,
                         const ndn::NackCallback& afterNacked,
                         const ndn::TimeoutCallback& afterTimeout,
                         int nRetries,
                         const ndn::security::DataValidationFailureCallback& afterValidationFailed)
{
  uint64_t id = ++m_interestIdCounter;
  const auto queuedAt = SteadyClock::now();
  m_interestQueue.push({
    id,
    interest,
    afterSatisfied,
    afterNacked,
    afterTimeout,
    nRetries,
    m_securityOptions.nRetriesOnValidationFail,
    afterValidationFailed,
    queuedAt,
    {},
  });
  m_queuedCount.fetch_add(1, std::memory_order_relaxed);
  processQueue();
}

void
Fetcher::expressInterest(const QueuedInterest& qi)
{
  QueuedInterest qiNew(qi);
  qiNew.id = ++m_interestIdCounter;

  Interest newNonceInterest(qiNew.interest);
  newNonceInterest.refreshNonce();
  qiNew.interest = newNonceInterest;
  qiNew.queuedAt = SteadyClock::now();
  qiNew.dispatchedAt = {};

  m_interestQueue.push(qiNew);
  m_queuedCount.fetch_add(1, std::memory_order_relaxed);
  processQueue();
}

void
Fetcher::processQueue()
{
  while (!m_interestQueue.empty() &&
         m_pendingInterests.size() < m_windowSize.load(std::memory_order_relaxed)) {
    QueuedInterest i = m_interestQueue.front();
    m_interestQueue.pop();
    m_queuedCount.fetch_sub(1, std::memory_order_relaxed);
    i.dispatchedAt = SteadyClock::now();
    const auto nonce = i.interest.getNonce();

    auto alive = m_alive;
    m_pendingInterests[i.id] = m_face.expressInterest(i.interest,
      [this, alive, i] (const Interest& interest, const Data& data) {
        if (alive->load(std::memory_order_relaxed)) {
          onData(interest, data, i);
        }
      },
      [this, alive, i] (const Interest& interest, const lp::Nack& nack) {
        if (alive->load(std::memory_order_relaxed)) {
          onNack(interest, nack, i);
        }
      },
      [this, alive, i] (const Interest& interest) {
        if (alive->load(std::memory_order_relaxed)) {
          onTimeout(interest, i);
        }
      });
    m_pendingCount.fetch_add(1, std::memory_order_relaxed);
    m_dispatchedCount.fetch_add(1, std::memory_order_relaxed);
    NDN_LOG_TRACE("event=fetcher_queued"
                  << " name=" << i.interest.getName()
                  << " nonce=" << nonce
                  << " attempt_id=" << i.id
                  << " retries_left=" << i.nRetries
                  << " queued_mono_ns=" << monotonicNs(i.queuedAt)
                  << " queue_us=" << elapsedUs(i.queuedAt, i.dispatchedAt));
    NDN_LOG_TRACE("event=fetcher_dispatched"
                  << " name=" << i.interest.getName()
                  << " nonce=" << nonce
                  << " attempt_id=" << i.id
                  << " retries_left=" << i.nRetries
                  << " lifetime_ms=" << i.interest.getInterestLifetime().count()
                  << " dispatch_mono_ns=" << monotonicNs(i.dispatchedAt)
                  << " queued=" << m_queuedCount.load(std::memory_order_relaxed)
                  << " pending=" << m_pendingCount.load(std::memory_order_relaxed));
  }
}

void
Fetcher::onData(const Interest& interest, const Data& data, const QueuedInterest& qi)
{
  const auto receivedAt = SteadyClock::now();
  m_dataCount.fetch_add(1, std::memory_order_relaxed);
  if (m_pendingInterests.erase(qi.id) != 0) {
    m_pendingCount.fetch_sub(1, std::memory_order_relaxed);
  }
  NDN_LOG_TRACE("event=fetcher_data"
                << " name=" << interest.getName()
                << " nonce=" << interest.getNonce()
                << " attempt_id=" << qi.id
                << " terminal_mono_ns=" << monotonicNs(receivedAt)
                << " pending_us=" << elapsedUs(qi.dispatchedAt, receivedAt)
                << " data_name=" << data.getName());
  processQueue();

  if (m_securityOptions.validator == nullptr) {
    // No validator provided
    NDN_LOG_TRACE("event=fetcher_validation_success"
                  << " name=" << interest.getName()
                  << " nonce=" << interest.getNonce()
                  << " attempt_id=" << qi.id
                  << " validator=none");
    qi.afterSatisfied(interest, data);
  } else {
    auto alive = m_alive;
    NDN_LOG_TRACE("event=fetcher_validation_start"
                  << " name=" << interest.getName()
                  << " nonce=" << interest.getNonce()
                  << " attempt_id=" << qi.id
                  << " data_mono_ns=" << monotonicNs(receivedAt));
    auto onDataValidated = [alive, qi](const Data& data) {
      if (alive->load(std::memory_order_relaxed)) {
        NDN_LOG_TRACE("event=fetcher_validation_success"
                      << " name=" << qi.interest.getName()
                      << " nonce=" << qi.interest.getNonce()
                      << " attempt_id=" << qi.id);
        qi.afterSatisfied(qi.interest, data);
      }
    };

    auto onValidationFailed = [this, alive, qi](const Data& data, const ValidationError& error) {
      if (!alive->load(std::memory_order_relaxed)) {
        return;
      }
      NDN_LOG_TRACE("event=fetcher_validation_failure"
                    << " name=" << qi.interest.getName()
                    << " nonce=" << qi.interest.getNonce()
                    << " attempt_id=" << qi.id
                    << " retries_left=" << qi.nRetriesOnValidationFail
                    << " error=" << error);
      if (qi.nRetriesOnValidationFail > 0) {
        this->m_scheduler.schedule(
          ndn::time::milliseconds(this->m_securityOptions.millisBeforeRetryOnValidationFail),
          [this, alive, qi] {
            if (!alive->load(std::memory_order_relaxed)) {
              return;
            }
            QueuedInterest qiNew(qi);
            qiNew.nRetriesOnValidationFail--;
            this->expressInterest(qiNew);
          });
        return;
      }

      if (qi.afterValidationFailed) {
        qi.afterValidationFailed(data, error);
      }
    };

    m_securityOptions.validator->validate(data, onDataValidated, onValidationFailed);
  }
}

void
Fetcher::onNack(const ndn::Interest& interest, const ndn::lp::Nack& nack, const QueuedInterest& qi)
{
  const auto terminalAt = SteadyClock::now();
  m_nackCount.fetch_add(1, std::memory_order_relaxed);
  if (m_pendingInterests.erase(qi.id) != 0) {
    m_pendingCount.fetch_sub(1, std::memory_order_relaxed);
  }
  NDN_LOG_TRACE("event=fetcher_nack"
                << " name=" << interest.getName()
                << " nonce=" << interest.getNonce()
                << " attempt_id=" << qi.id
                << " terminal_mono_ns=" << monotonicNs(terminalAt)
                << " pending_us=" << elapsedUs(qi.dispatchedAt, terminalAt)
                << " reason=" << nack.getReason());
  processQueue();
  qi.afterNacked(interest, nack);
}

void
Fetcher::onTimeout(const Interest& interest, const QueuedInterest& qi)
{
  const auto terminalAt = SteadyClock::now();
  m_timeoutCount.fetch_add(1, std::memory_order_relaxed);
  if (m_pendingInterests.erase(qi.id) != 0) {
    m_pendingCount.fetch_sub(1, std::memory_order_relaxed);
  }
  NDN_LOG_TRACE("event=fetcher_timeout"
                << " name=" << interest.getName()
                << " nonce=" << interest.getNonce()
                << " attempt_id=" << qi.id
                << " retries_left=" << qi.nRetries
                << " terminal_mono_ns=" << monotonicNs(terminalAt)
                << " pending_us=" << elapsedUs(qi.dispatchedAt, terminalAt));

  if (qi.nRetries == 0) {
    processQueue();
    return qi.afterTimeout(interest);
  }

  QueuedInterest qiNew(qi);
  qiNew.nRetries--;
  m_retryCount.fetch_add(1, std::memory_order_relaxed);
  expressInterest(qiNew);
}

} // namespace ndn::svs
