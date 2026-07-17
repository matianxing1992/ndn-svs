/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2023 University of California, Los Angeles
 *
 * This file is part of ndn-svs, synchronization library for distributed realtime
 * applications for NDN.
 */

#include "svspubsub.hpp"

#include "tests/boost-test.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn::tests {

using namespace ndn::svs;

BOOST_AUTO_TEST_SUITE(TestSVSPubSub)

BOOST_AUTO_TEST_CASE(TypedPiggybackLimitControlsPublicationQueue)
{
  DummyClientFace defaultFace;
  SVSPubSubOptions defaultOpts;
  defaultOpts.useTimestamp = false;
  SVSPubSub defaultPubsub("/sync/default", "/local/default", defaultFace,
                          [] (const std::vector<MissingDataInfo>&) {}, defaultOpts);

  DummyClientFace limitedFace;
  SVSPubSubOptions limitedOpts;
  limitedOpts.useTimestamp = false;
  limitedOpts.maxPiggyDataSize = 1;
  SVSPubSub limitedPubsub("/sync/limited", "/local/limited", limitedFace,
                          [] (const std::vector<MissingDataInfo>&) {}, limitedOpts);

  const std::string payload = "piggyback candidate";
  const auto bytes = make_span(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
  defaultPubsub.publish("/app/default", bytes);
  limitedPubsub.publish("/app/limited", bytes);

  auto defaultExtra = defaultPubsub.onGetExtraData(VersionVector());
  auto limitedExtra = limitedPubsub.onGetExtraData(VersionVector());
  defaultExtra.parse();
  limitedExtra.parse();

  BOOST_CHECK(defaultExtra.find(ndn::tlv::Data) != defaultExtra.elements_end());
  BOOST_CHECK(limitedExtra.find(ndn::tlv::Data) == limitedExtra.elements_end());
}

BOOST_AUTO_TEST_CASE(LatePiggyDataSatisfiesPendingFetch)
{
  DummyClientFace face;
  KeyChain keyChain("pib-memory:svspubsub-test", "tpm-memory:svspubsub-test");
  keyChain.createIdentity("/svspubsub-test");
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {}, opts);

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

  SeqNo seqNo = 7;
  pubsub.insertMapping("/peer", seqNo, "/app/item", {});
  BOOST_CHECK(pubsub.processMapping("/peer", seqNo));
  BOOST_CHECK_EQUAL(callbackCount, 0);

  Data piggyData("/app/item");
  const std::string payload = "piggy";
  piggyData.setContent(make_span(reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));
  keyChain.sign(piggyData);

  MappingList extra("/peer");
  extra.pairs.push_back({seqNo, {Name("/app/item"), {}}});
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
                   [] (const std::vector<MissingDataInfo>&) {}, opts);
  pubsub.subscribe("/app/item", [&] (const SVSPubSub::SubscriptionData& data) {
    ++callbackCount;
    payload.assign(reinterpret_cast<const char*>(data.data.data()), data.data.size());
    producer = data.producerPrefix;
    receivedSeq = data.seqNo;
  });

  SeqNo seqNo = 1;
  pubsub.insertMapping("/peer", seqNo, "/app/item", {});
  pubsub.processMapping("/peer", seqNo);

  Data piggyData("/app/item");
  const std::string body = "late";
  piggyData.setContent(make_span(reinterpret_cast<const uint8_t*>(body.data()), body.size()));
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
