/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2023 University of California, Los Angeles
 *
 * This file is part of ndn-svs, synchronization library for distributed realtime
 * applications for NDN.
 */

#include "svspubsub.hpp"
#include "tlv.hpp"

#include "tests/boost-test.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

#include <boost/asio/io_context.hpp>

#include <thread>

namespace ndn::tests {

using namespace ndn::svs;
using namespace std::chrono_literals;

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

static void
runIoFor(Face& face, time::milliseconds duration)
{
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(duration.count());
  while (std::chrono::steady_clock::now() < deadline) {
    face.getIoContext().restart();
    face.getIoContext().run_for(10ms);
    std::this_thread::sleep_for(1ms);
  }
}

static size_t
countChildBlocksOfType(Block block, uint32_t type)
{
  block.parse();
  size_t count = 0;
  for (const auto& child : block.elements()) {
    if (child.type() == type) {
      ++count;
    }
  }
  return count;
}

BOOST_AUTO_TEST_SUITE(TestSVSPubSub)

BOOST_AUTO_TEST_CASE(LatePiggyDataSatisfiesPendingFetch)
{
  DummyClientFace face;
  KeyChain keyChain("pib-memory:svspubsub-test", "tpm-memory:svspubsub-test");
  keyChain.createIdentity("/svspubsub-test");
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);

  size_t callbackCount = 0;
  std::string received;
  Name producer;
  SeqNo receivedSeq = 0;

  pubsub.subscribe("/app", [&] (const SVSPubSub::SubscriptionData& data) {
    ++callbackCount;
    received.assign(reinterpret_cast<const char*>(data.data.data()), data.data.size());
    producer = data.producerPrefix;
    receivedSeq = data.seqNo;
  });

  BootstrapTime bootstrapTime = 100;
  pubsub.insertMapping("/peer", bootstrapTime, 7, "/app/item", {});
  BOOST_CHECK(pubsub.processMapping("/peer", bootstrapTime, 7));
  BOOST_CHECK_EQUAL(callbackCount, 0);

  Data piggyData("/app/item");
  const std::string payload = "piggy";
  piggyData.setContent(make_span(reinterpret_cast<const uint8_t*>(payload.data()),
                                 payload.size()));
  keyChain.sign(piggyData);

  MappingList extra("/peer");
  extra.pairs.push_back({bootstrapTime, 7, {Name("/app/item"), {}}});
  Block params = extra.encode();
  params.push_back(piggyData.wireEncode());
  params.encode();

  VersionVector vv;
  pubsub.onRecvExtraData(params, vv);

  BOOST_CHECK_EQUAL(callbackCount, 1);
  BOOST_CHECK_EQUAL(received, payload);
  BOOST_CHECK_EQUAL(producer, Name("/peer"));
  BOOST_CHECK_EQUAL(receivedSeq, 7);

  pubsub.onRecvExtraData(params, vv);
  BOOST_CHECK_EQUAL(callbackCount, 1);
}

BOOST_AUTO_TEST_CASE(AsyncPublishQueuesWithoutImmediateFacePut)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);

  const std::string payload1 = "one";
  const std::string payload2 = "two";
  auto seq1 = pubsub.publishAsync("/app/one",
                                  make_span(reinterpret_cast<const uint8_t*>(payload1.data()),
                                            payload1.size()));
  auto seq2 = pubsub.publishAsync("/app/two",
                                  make_span(reinterpret_cast<const uint8_t*>(payload2.data()),
                                            payload2.size()));

  BOOST_CHECK_EQUAL(seq1, 1);
  BOOST_CHECK_EQUAL(seq2, 2);
  BOOST_CHECK_EQUAL(face.sentData.size(), 0);

  runIoUntil(face, [&] { return face.sentData.size() >= 2; });

  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/local"), 2);
  BOOST_REQUIRE_GE(face.sentData.size(), 2);
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

BOOST_AUTO_TEST_CASE(MappingFetchSuppressesDuplicateInFlightRange)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.mappingFetchRetries = 0;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);
  pubsub.subscribe("/app", [] (const SVSPubSub::SubscriptionData&) {});
  runIoFor(face, 5_ms);
  face.sentInterests.clear();

  MissingDataInfo missing;
  missing.nodeId = "/offline";
  missing.bootstrapTime = 300;
  missing.low = 1;
  missing.high = 2;

  pubsub.updateCallbackInternal({missing});
  runIoFor(face, 5_ms);
  BOOST_REQUIRE_EQUAL(face.sentInterests.size(), 1);
  const auto firstInterest = face.sentInterests.front().getName();

  pubsub.updateCallbackInternal({missing});
  BOOST_CHECK_EQUAL(face.sentInterests.size(), 1);
  BOOST_CHECK_EQUAL(face.sentInterests.front().getName(), firstInterest);
}

BOOST_AUTO_TEST_CASE(MappingFetchBackoffSuppressesRetryAfterTimeout)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.mappingFetchRetries = 0;
  opts.mappingFetchFailureBackoff = 30_s;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);
  pubsub.subscribe("/app", [] (const SVSPubSub::SubscriptionData&) {});
  runIoFor(face, 5_ms);
  face.sentInterests.clear();

  MissingDataInfo missing;
  missing.nodeId = "/offline";
  missing.bootstrapTime = 400;
  missing.low = 1;
  missing.high = 2;

  pubsub.updateCallbackInternal({missing});
  runIoFor(face, 5_ms);
  BOOST_REQUIRE_EQUAL(face.sentInterests.size(), 1);

  runIoFor(face, 2500_ms);
  pubsub.updateCallbackInternal({missing});
  BOOST_CHECK_EQUAL(face.sentInterests.size(), 1);
}

BOOST_AUTO_TEST_CASE(SmallDataIsPiggybackedAcrossMultipleRounds)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.piggybackRepeatCount = 2;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);

  const std::string payload = "repeat";
  pubsub.publish("/app/repeat",
                 make_span(reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));

  auto first = pubsub.onGetExtraData(VersionVector());
  auto second = pubsub.onGetExtraData(VersionVector());
  auto third = pubsub.onGetExtraData(VersionVector());

  BOOST_CHECK_GE(countChildBlocksOfType(first, ndn::tlv::Data), 1);
  BOOST_CHECK_GE(countChildBlocksOfType(second, ndn::tlv::Data), 1);
  BOOST_CHECK_EQUAL(countChildBlocksOfType(third, ndn::tlv::Data), 0);
}

BOOST_AUTO_TEST_CASE(PublicationFetchTimeoutBacksOffAndIncreasesLifetime)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.publicationFetchRetries = 1;
  opts.publicationFetchInnerRetries = 0;
  opts.publicationFetchWindow = 1;
  opts.publicationFetchInterestLifetime = 50_ms;
  opts.publicationFetchMinInterestLifetime = 50_ms;
  opts.publicationFetchMaxInterestLifetime = 400_ms;
  opts.publicationFetchFailureBackoff = 10_ms;
  opts.publicationFetchMaxBackoff = 100_ms;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);
  pubsub.subscribe("/app/item", [] (const SVSPubSub::SubscriptionData&) {});
  runIoFor(face, 5_ms);
  face.sentInterests.clear();

  BootstrapTime bootstrapTime = 500;
  pubsub.insertMapping("/peer", bootstrapTime, 1, "/app/item", {});
  BOOST_CHECK(pubsub.processMapping("/peer", bootstrapTime, 1));
  pubsub.fetchAll();
  runIoFor(face, 5_ms);
  auto getPublicationInterests = [&face] {
    std::vector<const Interest*> result;
    for (const auto& interest : face.sentInterests) {
      if (Name("/peer").isPrefixOf(interest.getName())) {
        result.push_back(&interest);
      }
    }
    return result;
  };
  auto publicationInterests = getPublicationInterests();
  BOOST_REQUIRE_EQUAL(publicationInterests.size(), 1);
  BOOST_CHECK_EQUAL(publicationInterests.back()->getInterestLifetime(), 50_ms);

  runIoFor(face, 90_ms);
  publicationInterests = getPublicationInterests();
  BOOST_REQUIRE_GE(publicationInterests.size(), 2);
  BOOST_CHECK_EQUAL(publicationInterests.back()->getInterestLifetime(), 100_ms);
}

BOOST_AUTO_TEST_CASE(RepairRequestRepiggybacksProducerData)
{
  DummyClientFace producerFace;
  SVSPubSubOptions producerOpts;
  producerOpts.useTimestamp = false;
  producerOpts.piggybackRepeatCount = 1;
  producerOpts.repairRequestRepeatCount = 1;

  SVSPubSub producer("/sync", "/producer", producerFace,
                     [] (const std::vector<MissingDataInfo>&) {},
                     producerOpts);

  const std::string payload = "repair";
  auto seq = producer.publish("/app/repair",
                              make_span(reinterpret_cast<const uint8_t*>(payload.data()),
                                        payload.size()));
  auto bootstrapTime = producer.getSVSync().getCore().getBootstrapTime();

  // Drain the initial one-shot piggyback so the later Data comes from repair.
  producer.onGetExtraData(VersionVector());
  BOOST_CHECK_EQUAL(countChildBlocksOfType(producer.onGetExtraData(VersionVector()),
                                           ndn::tlv::Data), 0);

  DummyClientFace receiverFace;
  SVSPubSubOptions receiverOpts;
  receiverOpts.useTimestamp = false;
  receiverOpts.repairRequestRepeatCount = 1;
  SVSPubSub receiver("/sync", "/receiver", receiverFace,
                     [] (const std::vector<MissingDataInfo>&) {},
                     receiverOpts);

  receiver.rememberRepairRequest(SVSPubSub::PublicationKey("/producer", bootstrapTime, seq));
  auto repairBlock = receiver.onGetExtraData(VersionVector());
  BOOST_CHECK_GE(countChildBlocksOfType(repairBlock, ndn::svs::tlv::RepairData), 1);

  producer.onRecvExtraData(repairBlock, VersionVector());
  auto repaired = producer.onGetExtraData(VersionVector());
  BOOST_CHECK_GE(countChildBlocksOfType(repaired, ndn::tlv::Data), 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
