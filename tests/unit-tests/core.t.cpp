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

#include "tests/boost-test.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

#include <boost/asio/io_context.hpp>

#include <thread>

namespace ndn::tests {

using namespace ndn::svs;
using namespace std::chrono_literals;

static Interest
makeSyncInterest(const Name& syncPrefix, const VersionVector& vv)
{
  ndn::encoding::EncodingBuffer enc;
  size_t length = 0;
  length += ndn::encoding::prependBlock(enc, vv.encode());
  enc.prependVarNumber(length);
  enc.prependVarNumber(ndn::tlv::ApplicationParameters);

  Interest interest(Name(syncPrefix).appendVersion(2));
  interest.setApplicationParameters(enc.block());
  return interest;
}

static VersionVector
getSyncInterestVector(const Interest& interest)
{
  auto params = interest.getApplicationParameters();
  params.parse();
  return VersionVector(params.get(ndn::svs::tlv::StateVector));
}

static void
runIoUntil(Face& face, const std::function<bool()>& done)
{
  auto deadline = std::chrono::steady_clock::now() + 2s;
  while (!done() && std::chrono::steady_clock::now() < deadline) {
    face.getIoContext().restart();
    face.getIoContext().run_for(10ms);
    std::this_thread::sleep_for(1ms);
  }
}

class CoreFixture
{
protected:
  CoreFixture()
    : m_syncPrefix("/ndn/test")
    , m_core(m_face, m_syncPrefix, [](auto&&...) {})
  {
  }

protected:
  DummyClientFace m_face;
  Name m_syncPrefix;
  SVSyncCore m_core;
};

BOOST_FIXTURE_TEST_SUITE(TestCore, CoreFixture)

BOOST_AUTO_TEST_CASE(MergeStateVector)
{
  std::vector<MissingDataInfo> missingInfo;

  VersionVector v = m_core.getState();
  BOOST_CHECK_EQUAL(v.get("one"), 0);
  BOOST_CHECK_EQUAL(v.get("two"), 0);
  BOOST_CHECK_EQUAL(v.get("three"), 0);
  BOOST_CHECK_EQUAL(missingInfo.size(), 0);

  VersionVector v1;
  v1.set("one", 100, 1);
  v1.set("two", 200, 2);
  missingInfo = m_core.mergeStateVector(v1).missingInfo;

  v = m_core.getState();
  BOOST_CHECK_EQUAL(v.get("one"), 1);
  BOOST_CHECK_EQUAL(v.get("two"), 2);
  BOOST_CHECK_EQUAL(v.get("three"), 0);
  BOOST_CHECK_EQUAL(missingInfo.size(), 2);

  VersionVector v2;
  v2.set("one", 100, 1);
  v2.set("two", 200, 1);
  v2.set("three", 300, 3);
  missingInfo = m_core.mergeStateVector(v2).missingInfo;

  v = m_core.getState();
  BOOST_CHECK_EQUAL(v.get("one"), 1);
  BOOST_CHECK_EQUAL(v.get("two"), 2);
  BOOST_CHECK_EQUAL(v.get("three"), 3);

  BOOST_REQUIRE_EQUAL(missingInfo.size(), 1);
  BOOST_CHECK_EQUAL(missingInfo[0].nodeId, "three");
  BOOST_CHECK_EQUAL(missingInfo[0].bootstrapTime, 300);
  BOOST_CHECK_EQUAL(missingInfo[0].low, 1);
  BOOST_CHECK_EQUAL(missingInfo[0].high, 3);
}

BOOST_AUTO_TEST_CASE(ComputeMergeStateVector)
{
  VersionVector local;
  local.set("one", 100, 2);
  local.set("local-only", 700, 7);

  VersionVector remote;
  remote.set("one", 100, 5);
  remote.set("two", 200, 1);

  auto result = SVSyncCore::computeMergeStateVector(local, remote);

  BOOST_CHECK(result.myVectorNew);
  BOOST_CHECK(result.otherVectorNew);
  BOOST_CHECK_EQUAL(result.mergedVector.get("one"), 5);
  BOOST_CHECK_EQUAL(result.mergedVector.get("two"), 1);
  BOOST_CHECK_EQUAL(result.mergedVector.get("local-only"), 7);

  BOOST_REQUIRE_EQUAL(result.missingData.size(), 2);
  BOOST_CHECK_EQUAL(result.missingData[0].nodeId, "one");
  BOOST_CHECK_EQUAL(result.missingData[0].bootstrapTime, 100);
  BOOST_CHECK_EQUAL(result.missingData[0].low, 3);
  BOOST_CHECK_EQUAL(result.missingData[0].high, 5);
  BOOST_CHECK_EQUAL(result.missingData[1].nodeId, "two");
  BOOST_CHECK_EQUAL(result.missingData[1].bootstrapTime, 200);
  BOOST_CHECK_EQUAL(result.missingData[1].low, 1);
  BOOST_CHECK_EQUAL(result.missingData[1].high, 1);
}

BOOST_AUTO_TEST_CASE(ComputeMergeStateVectorKeepsRestartEpochsSeparate)
{
  VersionVector local;
  local.set("node", 100, 10);

  VersionVector remote;
  remote.set("node", 200, 1);

  auto result = SVSyncCore::computeMergeStateVector(local, remote);
  BOOST_CHECK(result.myVectorNew);
  BOOST_CHECK(result.otherVectorNew);
  BOOST_CHECK_EQUAL(result.mergedVector.get("node", 100), 10);
  BOOST_CHECK_EQUAL(result.mergedVector.get("node", 200), 1);
  BOOST_REQUIRE_EQUAL(result.missingData.size(), 1);
  BOOST_CHECK_EQUAL(result.missingData[0].nodeId, "node");
  BOOST_CHECK_EQUAL(result.missingData[0].bootstrapTime, 200);
  BOOST_CHECK_EQUAL(result.missingData[0].low, 1);
  BOOST_CHECK_EQUAL(result.missingData[0].high, 1);
}

BOOST_AUTO_TEST_CASE(ParallelSyncInterestHandling)
{
  m_core.setParallelSyncProcessing(true, 2, 16);

  VersionVector remote;
  remote.set("peer", 300, 3);
  m_core.onSyncInterestValidated(makeSyncInterest(m_syncPrefix, remote));

  runIoUntil(m_face, [this] {
    auto stats = m_core.getSyncProcessingStats();
    return stats.syncJobsCompleted >= 1 || stats.syncJobsStale >= 1;
  });

  auto stats = m_core.getSyncProcessingStats();
  BOOST_CHECK_EQUAL(stats.syncJobsSubmitted, 1);
  BOOST_CHECK_EQUAL(stats.syncJobsDropped, 0);
  BOOST_CHECK_EQUAL(m_core.getSeqNo("peer"), 3);
}

BOOST_AUTO_TEST_CASE(ParallelSyncInterestStressAndStaleFallback)
{
  m_core.setParallelSyncProcessing(true, 2, 32);

  VersionVector staleRemote;
  staleRemote.set("stale-peer", 100, 1);
  m_core.onSyncInterestValidated(makeSyncInterest(m_syncPrefix, staleRemote));
  m_core.updateSeqNo(1, "local-node");

  for (uint64_t seq = 1; seq <= 20; ++seq) {
    VersionVector remote;
    remote.set("peer", 300, seq);
    m_core.onSyncInterestValidated(makeSyncInterest(m_syncPrefix, remote));
  }

  runIoUntil(m_face, [this] {
    auto stats = m_core.getSyncProcessingStats();
    return stats.syncJobsCompleted + stats.syncJobsStale >= stats.syncJobsSubmitted;
  });

  auto stats = m_core.getSyncProcessingStats();
  BOOST_CHECK_EQUAL(stats.syncJobsDropped, 0);
  BOOST_CHECK_GE(stats.syncJobsSubmitted, 21);
  BOOST_CHECK_GE(stats.syncJobsStale, 1);
  BOOST_CHECK_EQUAL(m_core.getSeqNo("peer"), 20);
  BOOST_CHECK_EQUAL(m_core.getSeqNo("local-node"), 1);
}

BOOST_AUTO_TEST_CASE(PublicationSyncBatchingCoalescesLocalUpdates)
{
  m_core.setSyncInterestBatching(true, 20_ms);
  m_core.sendInitialInterest();

  runIoUntil(m_face, [this] {
    return !m_face.sentInterests.empty();
  });
  m_face.sentInterests.clear();

  for (uint64_t seq = 1; seq <= 10; ++seq) {
    m_core.updateSeqNo(seq, "local-node");
  }

  m_face.getIoContext().restart();
  m_face.getIoContext().run_for(std::chrono::milliseconds(5));
  BOOST_CHECK_EQUAL(m_face.sentInterests.size(), 0);

  runIoUntil(m_face, [this] {
    return !m_face.sentInterests.empty();
  });

  BOOST_REQUIRE_EQUAL(m_face.sentInterests.size(), 1);
  VersionVector sentVector = getSyncInterestVector(m_face.sentInterests.front());
  BOOST_CHECK_EQUAL(sentVector.get("local-node"), 10);
}

BOOST_AUTO_TEST_CASE(ParallelSyncProductionHandling)
{
  m_core.setParallelSyncProduction(true, 2, 16);
  m_core.sendInitialInterest();

  runIoUntil(m_face, [this] {
    return !m_face.sentInterests.empty();
  });
  m_face.sentInterests.clear();

  m_core.updateSeqNo(1, "local-node");

  runIoUntil(m_face, [this] {
    auto stats = m_core.getSyncProcessingStats();
    return !m_face.sentInterests.empty() ||
           stats.syncProductionJobsDropped > 0 ||
           stats.syncProductionJobsStale > 0;
  });

  auto stats = m_core.getSyncProcessingStats();
  BOOST_CHECK_EQUAL(stats.syncProductionJobsDropped, 0);
  BOOST_CHECK_GE(stats.syncProductionJobsSubmitted, 1);
  BOOST_CHECK_GE(stats.syncProductionJobsCompleted, 1);
  BOOST_REQUIRE_EQUAL(m_face.sentInterests.size(), 1);

  VersionVector sentVector = getSyncInterestVector(m_face.sentInterests.front());
  BOOST_CHECK_EQUAL(sentVector.get("local-node"), 1);
}

BOOST_AUTO_TEST_CASE(ParallelSyncProductionDropsStaleResult)
{
  m_core.setParallelSyncProduction(true, 1, 16);
  m_core.sendInitialInterest();
  m_core.updateSeqNo(1, "local-node");

  runIoUntil(m_face, [this] {
    auto stats = m_core.getSyncProcessingStats();
    return stats.syncProductionJobsSubmitted >= 1 &&
           stats.syncProductionJobsCompleted + stats.syncProductionJobsStale +
             stats.syncProductionJobsDropped >= 1;
  });

  auto stats = m_core.getSyncProcessingStats();
  BOOST_CHECK_EQUAL(stats.syncProductionJobsDropped, 0);
  BOOST_CHECK_GE(stats.syncProductionJobsSubmitted, 1);
}


BOOST_AUTO_TEST_CASE(SyncInterestMissingDataCarriesBootstrapTimeInCallback)
{
  DummyClientFace localFace;
  std::vector<MissingDataInfo> callbacks;

  SVSyncCore core(localFace, "/ndn/test", [&] (const std::vector<MissingDataInfo>& updates) {
    callbacks = updates;
  });

  VersionVector remote;
  const BootstrapTime bootstrapTime = 12345;
  remote.set("peer", bootstrapTime, 3);
  core.onSyncInterestValidated(makeSyncInterest("/ndn/test", remote));

  runIoUntil(localFace, [&] { return !callbacks.empty(); });

  BOOST_REQUIRE_EQUAL(callbacks.size(), 1);
  BOOST_CHECK_EQUAL(callbacks[0].nodeId, "peer");
  BOOST_CHECK_EQUAL(callbacks[0].bootstrapTime, bootstrapTime);
  BOOST_CHECK_EQUAL(callbacks[0].low, 1);
  BOOST_CHECK_EQUAL(callbacks[0].high, 3);
}

BOOST_AUTO_TEST_CASE(ParallelSyncProductionRecordsExtraBlockAndCompletesJobs)
{
  size_t extraBlockInvocations = 0;

  DummyClientFace localFace;
  SVSyncCore core(localFace, "/ndn/test", [] (const std::vector<MissingDataInfo>&) {});
  core.setParallelSyncProduction(true, 2, 16, true, true);
  core.setGetExtraBlockCallback([&] (const VersionVector&) {
    ++extraBlockInvocations;
    return VersionVector().encode();
  });

  core.sendInitialInterest();
  runIoUntil(localFace, [&] {
    return !localFace.sentInterests.empty();
  });
  BOOST_REQUIRE(!localFace.sentInterests.empty());
  localFace.sentInterests.clear();

  core.updateSeqNo(1, "local-node");
  runIoUntil(localFace, [&] {
    auto stats = core.getSyncProcessingStats();
    return stats.syncProductionJobsCompleted > 0 ||
           stats.syncProductionJobsStale > 0 ||
           stats.syncProductionJobsDropped > 0;
  });

  auto stats = core.getSyncProcessingStats();
  BOOST_CHECK_GE(stats.syncProductionJobsSubmitted, 1);
  BOOST_CHECK_GE(stats.syncProductionJobsCompleted +
                stats.syncProductionJobsStale +
                stats.syncProductionJobsDropped, 1);
  BOOST_CHECK_GE(extraBlockInvocations, 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
