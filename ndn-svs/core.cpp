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

#include <chrono>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

namespace ndn::svs {

static inline BootstrapTime
getCurrentBootstrapTime()
{
  const auto now = time::toUnixTimestamp<time::seconds>(time::system_clock::now());
  return static_cast<BootstrapTime>(now.count());
}

SVSyncCore::SVSyncCore(ndn::Face& face,
                       const Name& syncPrefix,
                       const UpdateCallback& onUpdate,
                       const SecurityOptions& securityOptions,
                       const NodeID& nid,
                       std::optional<BootstrapTime> bootstrapTime)
  : m_face(face)
  , m_syncPrefix(Name(syncPrefix).appendVersion(3))
  , m_securityOptions(securityOptions)
  , m_id(nid)
  , m_bootstrapTime(bootstrapTime.value_or(getCurrentBootstrapTime()))
  , m_onUpdate(onUpdate)
  , m_maxSuppressionTime(200_ms)
  , m_periodicSyncTime(30_s)
  , m_periodicSyncJitter(0.1)
  , m_rng(ndn::random::getRandomNumberEngine())
  , m_retxDist(m_periodicSyncTime.count() * (1.0 - m_periodicSyncJitter),
               m_periodicSyncTime.count() * (1.0 + m_periodicSyncJitter))
  , m_intrReplyDist(0, m_maxSuppressionTime.count())
  , m_scheduler(m_face.getIoContext())
{
  const auto futureTolerance = time::duration_cast<time::seconds>(time::hours(24)).count();
  if (m_bootstrapTime > getCurrentBootstrapTime() + futureTolerance) {
    NDN_THROW(std::invalid_argument("bootstrap time is more than 24 hours in the future"));
  }
  // Register the versioned Sync Interest prefix.
  const std::weak_ptr<int> lifetime = m_lifetime;
  // Keep an unscoped handle to release a registration that completes after destruction.
  auto registration = std::make_shared<ndn::RegisteredPrefixHandle>();
  *registration = m_face.setInterestFilter(
    m_syncPrefix,
    [this, lifetime] (const auto&, const Interest& interest) {
      if (!lifetime.expired())
        onSyncInterest(interest);
    },
    [this, lifetime, registration] (auto&&...) {
      if (lifetime.expired()) {
        registration->unregister();
        return;
      }
      sendInitialInterest();
    },
    [this, lifetime] (auto&&...) {
      if (lifetime.expired())
        return;
      // Report the failure after the management validator returns.
      m_registrationFailureEvent =
        m_scheduler.schedule(0_ms, [] { NDN_THROW(Error("Failed to register sync prefix")); });
    });
  m_syncRegisteredPrefix = *registration;
}

SVSyncCore::~SVSyncCore()
{
  m_lifetime.reset();
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
  if (m_retxEvent)
    return;
  // Wait for 100ms before sending the first sync interest
  // This is necessary to give other things time to initialize
  m_retxEvent = m_scheduler.schedule(100_ms, [this] { retxSyncInterest(true); });
}

void
SVSyncCore::onSyncInterest(const Interest& interest)
{
  Data data;
  try {
    const auto& name = interest.getName();
    const bool hasValidName = name.size() == m_syncPrefix.size() + 1 &&
                              name.getPrefix(-1) == m_syncPrefix &&
                              name.get(-1).isParametersSha256Digest();
    const bool hasValidParameters =
      hasValidName && interest.hasApplicationParameters() && interest.isParametersDigestValid();
    if (!hasValidName || !hasValidParameters) {
      NDN_THROW(Error("invalid Sync Interest name or parameters digest"));
    }
    auto params = interest.getApplicationParameters();
    params.parse();
    const bool hasEmbeddedData =
      params.elements_size() == 1 && params.elements().front().type() == ndn::tlv::Data;
    if (!hasEmbeddedData) {
      NDN_THROW(Error("Sync Interest must contain one State Vector Data"));
    }
    data.wireDecode(params.elements().front());
    if (data.getName() != m_syncPrefix || !data.getSignatureValue().isValid()) {
      NDN_THROW(Error("invalid State Vector Data"));
    }
  }
  catch (const std::exception&) {
    return;
  }

  // Get incoming face (this is needed by NLSR)
  uint64_t incomingFace = 0;
  {
    auto tag = interest.getTag<ndn::lp::IncomingFaceIdTag>();
    if (tag) {
      incomingFace = tag->get();
    }
  }
  if (m_securityOptions.validator) {
    auto validator = m_securityOptions.validator;
    validator->validate(
      data,
      [this, lifetime = std::weak_ptr<int>(m_lifetime), incomingFace] (const Data& validated) {
        if (!lifetime.expired())
          onSyncInterestValidated(validated, incomingFace);
      },
      [] (const Data&, const auto&) {});
  }
  else {
    onSyncInterestValidated(data, incomingFace);
  }
}

void
SVSyncCore::onSyncInterestValidated(const Data& data, uint64_t incomingFace)
{
  std::shared_ptr<VersionVector> vvOther;
  Block extra;
  try {
    auto content = data.getContent();
    content.parse();
    const auto& elements = content.elements();
    const bool hasStateVector = !elements.empty() && elements.front().type() == tlv::StateVector;
    const bool hasValidExtension =
      hasStateVector && elements.size() <= 2 &&
      (elements.size() == 1 || elements.back().type() == tlv::MappingData);
    if (!hasStateVector || !hasValidExtension) {
      NDN_THROW(Error("invalid State Vector Data content"));
    }
    vvOther = std::make_shared<VersionVector>(elements.front());
    if (elements.size() == 2)
      extra = elements.back();
  }
  catch (const std::exception&) {
    return;
  }

  // Use piggyback mappings only after a configured validator has accepted the Data.
  if (extra.isValid() && m_recvExtraBlock && m_securityOptions.validator) {
    const std::weak_ptr<int> lifetime = m_lifetime;
    auto callback = m_recvExtraBlock;
    try {
      callback(extra, *vvOther);
    }
    catch (const std::exception&) {
    }
    if (lifetime.expired())
      return;
  }

  // Merge state vector
  auto result = mergeStateVector(*vvOther);

  // Finish protocol work before invoking application code, which may destroy us.
  if (!recordVector(*vvOther)) {
    if (!result.myVectorNew) {
      retxSyncInterest(false);
    }
    else if (!result.recentUpdatesOnly) {
      enterSuppressionState(*vvOther);
      int delay = suppressionCurve(m_maxSuppressionTime.count(), m_intrReplyDist(m_rng));
      retxSyncInterest(false, delay);
    }
  }

  if (!result.missingInfo.empty()) {
    for (auto& e : result.missingInfo)
      e.incomingFace = incomingFace;
    auto onUpdate = m_onUpdate;
    onUpdate(result.missingInfo);
  }
}

void
SVSyncCore::retxSyncInterest(bool send, int delay)
{
  if (send) {
    // Only send interest if in steady state or local vector has newer state
    // than recorded interests
    if (!m_recordedVv || mergeStateVector(*m_recordedVv).myVectorNew)
      sendSyncInterest();
    m_recordedVv = nullptr;
  }

  if (delay < 0)
    delay = m_retxDist(m_rng);

  m_retxEvent =
    m_scheduler.schedule(time::milliseconds(delay), [this] { retxSyncInterest(true); });
}

void
SVSyncCore::sendSyncInterest()
{
  VersionVector snapshot;
  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    snapshot = m_vv;
  }
  Data data(m_syncPrefix);
  Block content(ndn::tlv::Content);
  content.push_back(snapshot.encode());
  Block extra;
  if (m_getExtraBlock) {
    extra = m_getExtraBlock(snapshot);
    if (extra.isValid()) {
      if (extra.type() != tlv::MappingData)
        NDN_THROW(Error("extra block must be MappingData"));
      content.push_back(extra);
    }
  }
  Interest interest(m_syncPrefix);
  interest.setInterestLifetime(1_s);
  auto encodeParameters = [&] {
    content.encode();
    data.setContent(content);
    m_securityOptions.dataSigner->sign(data);
    Block params(ndn::tlv::ApplicationParameters);
    params.push_back(data.wireEncode());
    params.encode();
    interest.setApplicationParameters(params);
  };
  encodeParameters();
  if (extra.isValid() && interest.wireEncode().size() > ndn::MAX_NDN_PACKET_SIZE) {
    content.erase(content.elements_end() - 1);
    encodeParameters();
  }
  if (interest.wireEncode().size() > ndn::MAX_NDN_PACKET_SIZE)
    NDN_THROW(std::length_error("state vector exceeds the packet size limit"));

  m_face.expressInterest(interest, nullptr, nullptr, nullptr);
}

SVSyncCore::MergeResult
SVSyncCore::mergeStateVector(const VersionVector& vvOther)
{
  std::lock_guard<std::mutex> lock(m_vvMutex);
  SVSyncCore::MergeResult result;

  // Check if other vector has newer state
  for (const auto& entry : vvOther) {
    NodeID nidOther = entry.first;
    if (!m_vv.has(nidOther)) {
      m_vv.insert(nidOther);
      result.otherVectorNew = true;
    }
    for (const auto& seqEntry : entry.second) {
      BootstrapTime bootstrapTime = seqEntry.first;
      SeqNo seqOther = seqEntry.second;
      SeqNo seqCurrent = m_vv.get(nidOther, bootstrapTime);
      if (seqCurrent < seqOther) {
        result.otherVectorNew = true;
        SeqNo startSeq = seqCurrent + 1;
        result.missingInfo.push_back({nidOther, startSeq, seqOther, 0, bootstrapTime});
        m_vv.set(nidOther, bootstrapTime, seqOther);
      }
    }
  }

  // Check if I have newer state
  for (const auto& entry : m_vv) {
    NodeID nid = entry.first;
    if (!vvOther.has(nid)) {
      result.myVectorNew = true;
      if (time::system_clock::now() - m_vv.getLastUpdate(nid) >= m_maxSuppressionTime)
        result.recentUpdatesOnly = false;
    }
    for (const auto& seqEntry : entry.second) {
      BootstrapTime bootstrapTime = seqEntry.first;
      SeqNo seq = seqEntry.second;
      SeqNo seqOther = vvOther.get(nid, bootstrapTime);
      if (seqOther < seq) {
        result.myVectorNew = true;
        if (time::system_clock::now() - m_vv.getLastUpdate(nid) >= m_maxSuppressionTime)
          result.recentUpdatesOnly = false;
      }
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
  return m_vv.get(t_nid, m_bootstrapTime);
}

void
SVSyncCore::updateSeqNo(const SeqNo& seq, const NodeID& nid)
{
  NodeID t_nid = (nid == EMPTY_NODE_ID) ? m_id : nid;

  {
    std::lock_guard<std::mutex> lock(m_vvMutex);
    const SeqNo prev = m_vv.get(t_nid, m_bootstrapTime);
    if (seq == 0 || seq < prev)
      NDN_THROW(
        std::invalid_argument("local sequence number must be positive and cannot decrease"));
    if (seq == prev)
      return;
    m_vv.set(t_nid, m_bootstrapTime, seq);
  }

  if (m_face.getIoContext().get_executor().running_in_this_thread()) {
    retxSyncInterest(true);
  }
  else {
    boost::asio::post(m_face.getIoContext(), [this, lifetime = std::weak_ptr<int>(m_lifetime)] {
      if (!lifetime.expired())
        retxSyncInterest(true);
    });
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
  if (!m_recordedVv)
    return false;

  for (const auto& entry : vvOther) {
    NodeID nidOther = entry.first;
    m_recordedVv->insert(nidOther);
    for (const auto& seqEntry : entry.second) {
      BootstrapTime bootstrapTime = seqEntry.first;
      SeqNo seqOther = seqEntry.second;
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
  if (!m_recordedVv)
    m_recordedVv = std::make_unique<VersionVector>(vvOther);
}

} // namespace ndn::svs
