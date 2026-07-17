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

namespace ndn::svs {

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
  while (!m_interestQueue.empty()) {
    m_interestQueue.pop();
  }
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
  m_interestQueue.push({
    id,
    interest,
    afterSatisfied,
    afterNacked,
    afterTimeout,
    nRetries,
    m_securityOptions.nRetriesOnValidationFail,
    afterValidationFailed,
  });
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

  m_interestQueue.push(qiNew);
  processQueue();
}

void
Fetcher::processQueue()
{
  while (!m_interestQueue.empty() && m_pendingInterests.size() < m_windowSize) {
    QueuedInterest i = m_interestQueue.front();
    m_interestQueue.pop();

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
  }
}

void
Fetcher::onData(const Interest& interest, const Data& data, const QueuedInterest& qi)
{
  m_pendingInterests.erase(qi.id);
  processQueue();

  if (m_securityOptions.validator == nullptr) {
    // No validator provided
    qi.afterSatisfied(interest, data);
  } else {
    auto alive = m_alive;
    auto onDataValidated = [alive, qi](const Data& data) {
      if (alive->load(std::memory_order_relaxed)) {
        qi.afterSatisfied(qi.interest, data);
      }
    };

    auto onValidationFailed = [this, alive, qi](const Data& data, const ValidationError& error) {
      if (!alive->load(std::memory_order_relaxed)) {
        return;
      }
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
  m_pendingInterests.erase(qi.id);
  processQueue();
  qi.afterNacked(interest, nack);
}

void
Fetcher::onTimeout(const Interest& interest, const QueuedInterest& qi)
{
  m_pendingInterests.erase(qi.id);

  if (qi.nRetries == 0) {
    processQueue();
    return qi.afterTimeout(interest);
  }

  QueuedInterest qiNew(qi);
  qiNew.nRetries--;
  expressInterest(qiNew);
}

} // namespace ndn::svs
