/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2025 University of California, Los Angeles
 *
 * This file is part of ndn-svs, synchronization library for distributed realtime
 * applications for NDN.
 *
 * ndn-svs library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation in version 2.1 of the License.
 *
 * ndn-svs library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 */

#include "core.hpp"
#include "svspubsub.hpp"
#include "version-vector.hpp"

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

BOOST_AUTO_TEST_SUITE(TestSVSRegressionCommits)

BOOST_AUTO_TEST_CASE(VersionVectorRejectsTooFarFutureBootstrapTime)
{
  const auto now = static_cast<BootstrapTime>(
    std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());

  VersionVector vv;
  vv.set("peer", now + 2 * 86400, 1);

  BOOST_CHECK_THROW(VersionVector(vv.encode()), VersionVector::Error);
}

BOOST_AUTO_TEST_CASE(SyncInterestMissingDataCarriesBootstrapTimeInCallback)
{
  DummyClientFace face;
  std::vector<MissingDataInfo> callbacks;

  SVSyncCore core(face, "/ndn/test", [&] (const std::vector<MissingDataInfo>& updates) {
    callbacks = updates;
  });

  VersionVector remote;
  const BootstrapTime bootstrapTime = 12345;
  remote.set("peer", bootstrapTime, 3);
  core.onSyncInterestValidated(makeSyncInterest("/ndn/test", remote));

  BOOST_REQUIRE_EQUAL(callbacks.size(), 1);
  BOOST_CHECK_EQUAL(callbacks[0].nodeId, Name("peer"));
  BOOST_CHECK_EQUAL(callbacks[0].bootstrapTime, bootstrapTime);
  BOOST_CHECK_EQUAL(callbacks[0].low, 1);
  BOOST_CHECK_EQUAL(callbacks[0].high, 3);
}

BOOST_AUTO_TEST_CASE(ParallelSyncProductionRecordsExtraBlockAndCompletesJobs)
{
  DummyClientFace face;
  size_t extraBlockInvocations = 0;

  SVSyncCore core(face, "/ndn/test", [] (const std::vector<MissingDataInfo>&) {});
  core.setParallelSyncProduction(true, 2, 16, true, true);
  core.setGetExtraBlockCallback([&] (const VersionVector&) {
    ++extraBlockInvocations;
    return VersionVector().encode();
  });

  core.sendInitialInterest();
  runIoUntil(face, [&] {
    return !face.sentInterests.empty();
  });
  BOOST_REQUIRE(!face.sentInterests.empty());
  face.sentInterests.clear();

  core.updateSeqNo(1, "local");
  runIoUntil(face, [&] {
    return core.getSyncProcessingStats().syncProductionJobsCompleted > 0 ||
           core.getSyncProcessingStats().syncJobsCompleted > 0;
  });

  BOOST_CHECK_GE(core.getSyncProcessingStats().syncProductionJobsSubmitted, 1);
  BOOST_CHECK_GE(core.getSyncProcessingStats().syncProductionJobsCompleted +
                core.getSyncProcessingStats().syncProductionJobsStale +
                core.getSyncProcessingStats().syncProductionJobsDropped, 1);
  BOOST_CHECK_GE(extraBlockInvocations, 1);
}

BOOST_AUTO_TEST_CASE(AsyncPublishNameOnlyAndPacketAreQueuedAndCommitted)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);

  auto seq1 = pubsub.publishAsync("/app/name-only", Name("/provider"));
  Data packet("/app/packet");
  const std::string body = "abc";
  packet.setContent(make_span(reinterpret_cast<const uint8_t*>(body.data()), body.size()));
  auto seq2 = pubsub.publishPacketAsync(packet, Name("/provider"));

  BOOST_CHECK_EQUAL(seq2, seq1 + 1);
  BOOST_CHECK_EQUAL(face.sentData.size(), 0);

  runIoUntil(face, [&] {
    return !face.sentData.empty();
  });
  BOOST_CHECK_GE(face.sentInterests.size() + face.sentData.size(), 1);
}

BOOST_AUTO_TEST_CASE(LatePiggyDataStillSatisfiesPendingFetch)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  KeyChain keyChain("pib-memory:svspubsub-test", "tpm-memory:svspubsub-test");
  keyChain.createIdentity("/svspubsub-test");

  size_t callbackCount = 0;
  std::string payload;
  Name producer;
  SeqNo receivedSeq = 0;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);
  pubsub.subscribe("/app/item", [&] (const SVSPubSub::SubscriptionData& data) {
    ++callbackCount;
    payload.assign(reinterpret_cast<const char*>(data.data.data()), data.data.size());
    producer = data.producerPrefix;
    receivedSeq = data.seqNo;
  });

  BootstrapTime bootstrapTime = 200;
  pubsub.insertMapping("/peer", bootstrapTime, 1, "/app/item", {});
  pubsub.processMapping("/peer", bootstrapTime, 1);

  Data piggyData("/app/item");
  const std::string body = "late";
  piggyData.setContent(make_span(reinterpret_cast<const uint8_t*>(body.data()),
                                body.size()));
  keyChain.sign(piggyData);

  MappingList extra("/peer");
  Block params = extra.encode();
  params.push_back(piggyData.wireEncode());
  params.encode();

  pubsub.onRecvExtraData(params, VersionVector());
  BOOST_CHECK_EQUAL(callbackCount, 1);
  BOOST_CHECK_EQUAL(payload, body);
  BOOST_CHECK_EQUAL(producer, Name("/peer"));
  BOOST_CHECK_EQUAL(receivedSeq, 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
