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

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <boost/asio/io_context.hpp>

#include <limits>
#include <map>
#include <thread>

namespace ndn::tests {

using namespace ndn::svs;
using namespace std::chrono_literals;

BOOST_AUTO_TEST_CASE(ExplicitV2ProfilePropagatesThroughPubSub)
{
  DummyClientFace face;
  SVSPubSubOptions options;
  options.syncProtocol.version = SvsProtocolVersion::V2;
  SVSPubSub pubsub("/ndn/test/profile", "/node", face, [] (const auto&) {}, options);
  BOOST_CHECK(pubsub.getSyncProtocolOptions().version == SvsProtocolVersion::V2);
  BOOST_CHECK_EQUAL(pubsub.getSyncProtocolOptions().syncInterestLifetime, 1_ms);
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

class ThrowingDataSigner final : public BaseSigner
{
public:
  explicit ThrowingDataSigner(KeyChain& keyChain)
    : m_delegate(keyChain)
  {
  }

  void sign(Data& data) const override
  {
    const auto call = ++m_calls;
    if (call == m_failAt) {
      throw std::runtime_error("injected Data signing failure");
    }
    m_delegate.sign(data);
  }

  void failAt(size_t call) { m_failAt = call; }
  void disableFailure() { m_failAt = std::numeric_limits<size_t>::max(); }

private:
  KeyChainSigner m_delegate;
  mutable size_t m_calls = 0;
  size_t m_failAt = std::numeric_limits<size_t>::max();
};

class ThrowingDataStore final : public DataStore
{
public:
  void insert(const Data& data) override
  {
    const auto call = ++m_insertCalls;
    if (call == m_failAt) {
      throw std::runtime_error("injected Data store failure");
    }
    m_packets[data.getName()] = data;
  }

  std::shared_ptr<const Data> find(const Interest& interest) override
  {
    for (const auto& [name, data] : m_packets) {
      if (interest.matchesData(data)) {
        return std::make_shared<Data>(data);
      }
    }
    return nullptr;
  }

  void erase(const Name& name) override
  {
    m_erasedNames.push_back(name);
    m_packets.erase(name);
  }

  bool supportsErase() const noexcept override { return true; }
  void failAt(size_t call) { m_failAt = call; }
  void disableFailure() { m_failAt = std::numeric_limits<size_t>::max(); }
  size_t size() const { return m_packets.size(); }
  const std::map<Name, Data>& packets() const { return m_packets; }
  const std::vector<Name>& erasedNames() const { return m_erasedNames; }

private:
  size_t m_insertCalls = 0;
  size_t m_failAt = std::numeric_limits<size_t>::max();
  std::map<Name, Data> m_packets;
  std::vector<Name> m_erasedNames;
};

class UnsupportedRollbackStore final : public DataStore
{
public:
  std::shared_ptr<const Data> find(const Interest&) override { return nullptr; }
  void insert(const Data&) override { ++m_insertCalls; }
  size_t m_insertCalls = 0;
};

static std::vector<uint8_t>
makePayload(size_t size)
{
  std::vector<uint8_t> payload(size);
  for (size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<uint8_t>((i * 131 + 17) & 0xff);
  }
  return payload;
}

static Data
makeSignedOuterPacketOfSize(KeyChain& keyChain, size_t target)
{
  for (size_t namePadding = 0; namePadding <= 32; ++namePadding) {
    for (size_t payloadSize = target > 1024 ? target - 1024 : 0;
         payloadSize <= target; ++payloadSize) {
      Data inner(Name("/app/boundary").append(std::string(namePadding, 'n')));
      inner.setContent(makePayload(payloadSize));
      keyChain.sign(inner, security::signingWithSha256());

      Data outer(Name("/producer/sync/1/1").append(std::string(namePadding, 'o')));
      outer.setContent(inner.wireEncode());
      outer.setContentType(ndn::tlv::Data);
      keyChain.sign(outer, security::signingWithSha256());
      if (outer.wireEncode().size() == target) {
        return outer;
      }
    }
  }
  throw std::runtime_error("unable to construct requested signed outer wire size");
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
  const auto bytes = make_span(reinterpret_cast<const uint8_t*>(payload.data()),
                               payload.size());
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
  KeyChain packetKeyChain;
  packetKeyChain.sign(packet, signingWithSha256());
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
  runIoFor(face, 20_ms);
  face.sentInterests.clear();

  MissingDataInfo missing;
  missing.nodeId = "/offline";
  missing.bootstrapTime = 300;
  missing.low = 1;
  missing.high = 2;

  pubsub.updateCallbackInternal({missing});
  runIoUntil(face, [&] { return !face.sentInterests.empty(); });
  BOOST_REQUIRE_EQUAL(face.sentInterests.size(), 1);
  const auto firstInterest = face.sentInterests.front().getName();

  pubsub.updateCallbackInternal({missing});
  BOOST_CHECK_EQUAL(face.sentInterests.size(), 1);
  BOOST_CHECK_EQUAL(face.sentInterests.front().getName(), firstInterest);
}

BOOST_AUTO_TEST_CASE(SegmentedPublicationFitsFinalSignedOuterBoundary)
{
  KeyChain boundaryKeyChain("pib-memory:svspubsub-outer-boundary",
                            "tpm-memory:svspubsub-outer-boundary");
  boundaryKeyChain.createIdentity("/svspubsub-test/outer-boundary");
  const auto below = makeSignedOuterPacketOfSize(boundaryKeyChain, MAX_NDN_PACKET_SIZE - 1);
  const auto exact = makeSignedOuterPacketOfSize(boundaryKeyChain, MAX_NDN_PACKET_SIZE);
  const auto above = makeSignedOuterPacketOfSize(boundaryKeyChain, MAX_NDN_PACKET_SIZE + 1);
  BOOST_CHECK(SVSPubSub::isFinalPacketSizeAllowed(below.wireEncode().size()));
  BOOST_CHECK(SVSPubSub::isFinalPacketSizeAllowed(exact.wireEncode().size()));
  BOOST_CHECK(!SVSPubSub::isFinalPacketSizeAllowed(above.wireEncode().size()));

  for (const auto& applicationName : {Name("/short"), Name("/a/very/long/application/name")}) {
    DummyClientFace face;
    KeyChain keyChain("pib-memory:svspubsub-boundary", "tpm-memory:svspubsub-boundary");
    keyChain.createIdentity("/svspubsub-test/a/long/certificate/identity/for/segment/signing");
    SecurityOptions securityOptions(keyChain);
    auto store = std::make_shared<ThrowingDataStore>();
    SVSPubSubOptions opts;
    opts.useTimestamp = false;
    opts.dataStore = store;
    SVSPubSub pubsub("/sync", "/producer", face,
                     [] (const std::vector<MissingDataInfo>&) {}, opts, securityOptions);

    for (const auto payloadSize : {size_t(6500), size_t(7999), size_t(8000),
                                   size_t(8001), size_t(16000)}) {
      const auto before = store->size();
      const auto payload = makePayload(payloadSize);
      BOOST_CHECK_NO_THROW(pubsub.publish(applicationName, payload));
      BOOST_REQUIRE_GT(store->size(), before);
      std::vector<uint8_t> reconstructed;
      for (auto it = std::next(store->packets().begin(), before); it != store->packets().end(); ++it) {
        const auto& outer = it->second;
        BOOST_CHECK_LE(outer.wireEncode().size(), MAX_NDN_PACKET_SIZE);
        Data inner(outer.getContent().blockFromValue());
        const auto content = inner.getContent().value_bytes();
        reconstructed.insert(reconstructed.end(), content.begin(), content.end());
      }
      BOOST_CHECK_EQUAL_COLLECTIONS(reconstructed.begin(), reconstructed.end(),
                                    payload.begin(), payload.end());
    }
  }
}

BOOST_AUTO_TEST_CASE(FailedSegmentPreparationDoesNotAdvanceVisibleSequence)
{
  DummyClientFace face;
  KeyChain keyChain("pib-memory:svspubsub-sign-failure",
                    "tpm-memory:svspubsub-sign-failure");
  keyChain.createIdentity("/svspubsub-test/signer");
  SecurityOptions securityOptions(keyChain);
  auto signer = std::make_shared<ThrowingDataSigner>(keyChain);
  signer->failAt(3);
  securityOptions.dataSigner = signer;
  auto store = std::make_shared<ThrowingDataStore>();
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.dataStore = store;
  SVSPubSub pubsub("/sync", "/producer", face,
                   [] (const std::vector<MissingDataInfo>&) {}, opts, securityOptions);

  BOOST_CHECK_THROW(pubsub.publishAsync("/app/large", makePayload(16000)), std::runtime_error);
  runIoFor(face, 20_ms);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
  BOOST_CHECK_EQUAL(store->size(), 0);
  signer->disableFailure();
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/small", makePayload(64)), 1);
  runIoUntil(face, [&] { return pubsub.getSVSync().getCore().getSeqNo("/producer") == 1; });
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 1);
}

BOOST_AUTO_TEST_CASE(FailedSegmentStorageRollsBackAndKeepsProviderHealthy)
{
  DummyClientFace face;
  auto store = std::make_shared<ThrowingDataStore>();
  store->failAt(2);
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.dataStore = store;
  SVSPubSub pubsub("/sync", "/producer", face,
                   [] (const std::vector<MissingDataInfo>&) {}, opts);
  BOOST_CHECK_THROW(pubsub.publishAsync("/app/large", makePayload(16000)), std::runtime_error);
  runIoFor(face, 20_ms);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
  BOOST_CHECK_EQUAL(store->size(), 0);
  BOOST_REQUIRE_EQUAL(store->erasedNames().size(), 1);
  store->disableFailure();
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/small", makePayload(64)), 1);
  runIoUntil(face, [&] { return pubsub.getSVSync().getCore().getSeqNo("/producer") == 1; });
}

BOOST_AUTO_TEST_CASE(FailedAsyncFacePutFallsBackToStoredPublication)
{
  DummyClientFace face;
  auto store = std::make_shared<ThrowingDataStore>();
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.dataStore = store;
  SVSPubSub pubsub("/sync", "/producer", face,
                   [] (const std::vector<MissingDataInfo>&) {}, opts);
  size_t putCalls = 0;
  pubsub.getSVSync().setPreparedDataPutHookForTest([&] (const Data&) {
    ++putCalls;
    throw std::runtime_error("injected Face::put failure");
  });
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/first", makePayload(64)), 1);
  runIoUntil(face, [&] { return pubsub.getSVSync().getCore().getSeqNo("/producer") == 1; });
  BOOST_CHECK_EQUAL(putCalls, 1);
  pubsub.getSVSync().setPreparedDataPutHookForTest({});
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/second", makePayload(64)), 2);
  runIoUntil(face, [&] { return pubsub.getSVSync().getCore().getSeqNo("/producer") == 2; });
}

BOOST_AUTO_TEST_CASE(CommitFailureBlocksLaterPublicationUntilOrderedRetry)
{
  DummyClientFace face;
  auto store = std::make_shared<ThrowingDataStore>();
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.dataStore = store;
  opts.asyncCommitRetryInitial = 100_ms;
  SVSPubSub pubsub("/sync", "/producer", face,
                   [] (const std::vector<MissingDataInfo>&) {}, opts);
  size_t attempts = 0;
  pubsub.setPreparedPublicationCommitHookForTest([&] (SeqNo seqNo) {
    if (seqNo == 1 && ++attempts == 1) {
      throw std::runtime_error("injected commit-head failure");
    }
  });
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/one", makePayload(64)), 1);
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/two", makePayload(64)), 2);
  runIoFor(face, 20_ms);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
  BOOST_CHECK_EQUAL(pubsub.getPreparedPublicationCountForTest("/producer"), 2);
  runIoUntil(face, [&] { return pubsub.getSVSync().getCore().getSeqNo("/producer") == 2; });
  BOOST_CHECK_EQUAL(pubsub.getPreparedPublicationCountForTest("/producer"), 0);
}

BOOST_AUTO_TEST_CASE(PersistentCommitFailureIsReclaimedOnShutdown)
{
  DummyClientFace face;
  auto store = std::make_shared<ThrowingDataStore>();
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.dataStore = store;
  opts.asyncCommitRetryInitial = 100_ms;
  {
    SVSPubSub pubsub("/sync", "/producer", face,
                     [] (const std::vector<MissingDataInfo>&) {}, opts);
    pubsub.setPreparedPublicationCommitHookForTest([] (SeqNo) {
      throw std::runtime_error("persistent commit-head failure");
    });
    BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/blocked", makePayload(64)), 1);
    runIoFor(face, 20_ms);
    BOOST_CHECK_GT(store->size(), 0);
  }
  BOOST_CHECK_EQUAL(store->size(), 0);
}

BOOST_AUTO_TEST_CASE(UnsupportedRollbackStoreIsRejectedBeforeSinglePacketInsert)
{
  DummyClientFace face;
  auto store = std::make_shared<UnsupportedRollbackStore>();
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.dataStore = store;
  SVSPubSub pubsub("/sync", "/producer", face,
                   [] (const std::vector<MissingDataInfo>&) {}, opts);
  BOOST_CHECK_THROW(pubsub.publishAsync("/app/one", makePayload(64)), std::logic_error);
  BOOST_CHECK_EQUAL(store->m_insertCalls, 0);
}

BOOST_AUTO_TEST_CASE(ShutdownRollsBackStoredButUnadvertisedPublication)
{
  DummyClientFace face;
  auto store = std::make_shared<ThrowingDataStore>();
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.dataStore = store;
  {
    SVSPubSub pubsub("/sync", "/producer", face,
                     [] (const std::vector<MissingDataInfo>&) {}, opts);
    BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/staged", makePayload(16000)), 1);
    BOOST_CHECK_GT(store->size(), 0);
  }
  BOOST_CHECK_EQUAL(store->size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
