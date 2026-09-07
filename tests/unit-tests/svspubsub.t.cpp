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
#include <ndn-cxx/security/signing-helpers.hpp>

#include <boost/asio/io_context.hpp>

#include <limits>
#include <map>
#include <set>
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

BOOST_AUTO_TEST_CASE(PublicationPreparationWorkerModeIsDefaultOffAndSingleOnly)
{
  DummyClientFace inlineFace;
  SVSPubSubOptions inlineOptions;
  SVSPubSub inlinePubsub("/sync/inline", "/node/inline", inlineFace,
                         [] (const auto&) {}, inlineOptions);
  BOOST_CHECK_EQUAL(inlinePubsub.getPublicationPreparationWorkerCount(), 0);

  DummyClientFace workerFace;
  SVSPubSubOptions workerOptions;
  workerOptions.publicationPreparationWorkers = 1;
  workerOptions.publicationPreparationQueueCapacity = 8;
  SVSPubSub workerPubsub("/sync/worker", "/node/worker", workerFace,
                         [] (const auto&) {}, workerOptions);
  BOOST_CHECK_EQUAL(workerPubsub.getPublicationPreparationWorkerCount(), 1);

  DummyClientFace invalidFace;
  SVSPubSubOptions invalidOptions;
  invalidOptions.publicationPreparationWorkers = 2;
  BOOST_CHECK_THROW(
    SVSPubSub("/sync/invalid", "/node/invalid", invalidFace,
              [] (const auto&) {}, invalidOptions),
    std::invalid_argument);
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

class ThrowingDataSigner final : public BaseSigner
{
public:
  explicit ThrowingDataSigner(KeyChain& keyChain)
    : m_delegate(keyChain)
  {
  }

  void
  sign(Data& data) const override
  {
    const auto call = ++m_calls;
    if (call == m_failAt) {
      throw std::runtime_error("injected Data signing failure");
    }
    m_delegate.sign(data);
  }

  void
  failAt(size_t call)
  {
    m_failAt = call;
  }

  void
  disableFailure()
  {
    m_failAt = std::numeric_limits<size_t>::max();
  }

private:
  KeyChainSigner m_delegate;
  mutable size_t m_calls = 0;
  size_t m_failAt = std::numeric_limits<size_t>::max();
};

class ThreadRecordingDataSigner final : public BaseSigner
{
public:
  explicit ThreadRecordingDataSigner(KeyChain& keyChain)
    : m_delegate(keyChain)
  {
  }

  void
  sign(Data& data) const override
  {
    m_delegate.sign(data);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_threads.push_back(std::this_thread::get_id());
  }

  std::vector<std::thread::id>
  threads() const
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_threads;
  }

private:
  mutable KeyChainSigner m_delegate;
  mutable std::mutex m_mutex;
  mutable std::vector<std::thread::id> m_threads;
};

class ThrowingDataStore final : public DataStore
{
public:
  void
  insert(const Data& data) override
  {
    const auto call = ++m_insertCalls;
    if (call == m_failAt) {
      throw std::runtime_error("injected Data store failure");
    }
    m_packets[data.getName()] = data;
  }

  std::shared_ptr<const Data>
  find(const Interest& interest) override
  {
    for (const auto& [name, data] : m_packets) {
      if (interest.matchesData(data)) {
        return std::make_shared<Data>(data);
      }
    }
    return nullptr;
  }

  void
  erase(const Name& name) override
  {
    m_erasedNames.push_back(name);
    m_packets.erase(name);
  }

  bool
  supportsErase() const noexcept override
  {
    return true;
  }

  void
  failAt(size_t call)
  {
    m_failAt = call;
  }

  void
  disableFailure()
  {
    m_failAt = std::numeric_limits<size_t>::max();
  }

  size_t
  size() const
  {
    return m_packets.size();
  }

  const std::map<Name, Data>&
  packets() const
  {
    return m_packets;
  }

  const std::vector<Name>&
  erasedNames() const
  {
    return m_erasedNames;
  }

private:
  size_t m_insertCalls = 0;
  size_t m_failAt = std::numeric_limits<size_t>::max();
  std::map<Name, Data> m_packets;
  std::vector<Name> m_erasedNames;
};

class UnsupportedRollbackStore final : public DataStore
{
public:
  std::shared_ptr<const Data> find(const Interest&) override
  {
    return nullptr;
  }

  void insert(const Data&) override
  {
    ++m_insertCalls;
  }

  size_t m_insertCalls = 0;
};

class DeferredValidator final : public BaseValidator
{
public:
  void
  validate(const Data& data,
           const security::DataValidationSuccessCallback& success,
           const security::DataValidationFailureCallback& failure) override
  {
    m_data = data;
    m_success = success;
    m_failure = failure;
  }

  void
  succeed()
  {
    BOOST_REQUIRE(m_success);
    auto callback = std::move(m_success);
    m_failure = nullptr;
    callback(m_data);
  }

  void
  reject()
  {
    BOOST_REQUIRE(m_failure);
    auto callback = std::move(m_failure);
    m_success = nullptr;
    callback(m_data, ValidationError(1, "injected validation failure"));
  }

private:
  Data m_data;
  security::DataValidationSuccessCallback m_success;
  security::DataValidationFailureCallback m_failure;
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

static Block
makeInnerSegment(KeyChain& keyChain, const Name& baseName, size_t segmentNo,
                 size_t finalSegment, span<const uint8_t> content)
{
  Data inner(Name(baseName).appendVersion(0).appendSegment(segmentNo));
  inner.setContent(content);
  inner.setFinalBlock(name::Component::fromSegment(finalSegment));
  keyChain.sign(inner);
  return inner.wireEncode();
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
  const auto defaultStats = defaultPubsub.getPiggybackStats();
  const auto limitedStats = limitedPubsub.getPiggybackStats();
  BOOST_CHECK_EQUAL(defaultStats.preparedCount, 1);
  BOOST_CHECK_EQUAL(defaultStats.eligiblePrepared, 1);
  BOOST_CHECK_EQUAL(defaultStats.ineligiblePrepared, 0);
  BOOST_CHECK_GE(defaultStats.preparedWireBytesMax, payload.size());
  BOOST_CHECK_GE(defaultStats.sent, 1);
  BOOST_CHECK_EQUAL(limitedStats.preparedCount, 1);
  BOOST_CHECK_EQUAL(limitedStats.eligiblePrepared, 0);
  BOOST_CHECK_EQUAL(limitedStats.ineligiblePrepared, 1);
  BOOST_CHECK_EQUAL(limitedStats.sent, 0);
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

BOOST_AUTO_TEST_CASE(RejectedPiggyDataIsNotDeliveredToSubscribers)
{
  DummyClientFace face;
  KeyChain keyChain("pib-memory:svspubsub-piggy-validation",
                    "tpm-memory:svspubsub-piggy-validation");
  keyChain.createIdentity("/svspubsub-test/piggy-validation");
  SecurityOptions securityOptions(keyChain);
  auto validator = std::make_shared<DeferredValidator>();
  securityOptions.encapsulatedDataValidator = validator;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts, securityOptions);

  size_t callbackCount = 0;
  pubsub.subscribe("/app", [&] (const SVSPubSub::SubscriptionData&) {
    ++callbackCount;
  });

  const BootstrapTime bootstrapTime = 101;
  pubsub.insertMapping("/peer", bootstrapTime, 8, "/app/item", {});
  BOOST_CHECK(pubsub.processMapping("/peer", bootstrapTime, 8));

  Data piggyData("/app/item");
  const std::string payload = "untrusted piggyback";
  piggyData.setContent(make_span(reinterpret_cast<const uint8_t*>(payload.data()),
                                 payload.size()));
  keyChain.sign(piggyData);

  MappingList extra("/peer");
  extra.pairs.push_back({bootstrapTime, 8, {Name("/app/item"), {}}});
  Block params = extra.encode();
  params.push_back(piggyData.wireEncode());
  params.encode();

  pubsub.onRecvExtraData(params, VersionVector());
  BOOST_CHECK_EQUAL(callbackCount, 0);

  validator->reject();
  BOOST_CHECK_EQUAL(callbackCount, 0);
}

BOOST_AUTO_TEST_CASE(ValidatedPiggyDataIsDeliveredExactlyOnce)
{
  DummyClientFace face;
  KeyChain keyChain("pib-memory:svspubsub-piggy-validation-success",
                    "tpm-memory:svspubsub-piggy-validation-success");
  keyChain.createIdentity("/svspubsub-test/piggy-validation-success");
  SecurityOptions securityOptions(keyChain);
  auto validator = std::make_shared<DeferredValidator>();
  securityOptions.encapsulatedDataValidator = validator;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts, securityOptions);

  size_t callbackCount = 0;
  std::string received;
  pubsub.subscribe("/app", [&] (const SVSPubSub::SubscriptionData& data) {
    ++callbackCount;
    received.assign(reinterpret_cast<const char*>(data.data.data()), data.data.size());
  });

  const BootstrapTime bootstrapTime = 102;
  pubsub.insertMapping("/peer", bootstrapTime, 9, "/app/item", {});
  BOOST_CHECK(pubsub.processMapping("/peer", bootstrapTime, 9));

  Data piggyData("/app/item");
  const std::string payload = "trusted piggyback";
  piggyData.setContent(make_span(reinterpret_cast<const uint8_t*>(payload.data()),
                                 payload.size()));
  keyChain.sign(piggyData);

  MappingList extra("/peer");
  extra.pairs.push_back({bootstrapTime, 9, {Name("/app/item"), {}}});
  Block params = extra.encode();
  params.push_back(piggyData.wireEncode());
  params.encode();

  pubsub.onRecvExtraData(params, VersionVector());
  BOOST_CHECK_EQUAL(callbackCount, 0);

  validator->succeed();
  BOOST_CHECK_EQUAL(callbackCount, 1);
  BOOST_CHECK_EQUAL(received, payload);

  pubsub.onRecvExtraData(params, VersionVector());
  BOOST_CHECK_EQUAL(callbackCount, 1);
}

BOOST_AUTO_TEST_CASE(RepeatedMappingDoesNotDuplicatePendingSubscription)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.maxPiggyDataSize = 1;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);

  size_t callbackCount = 0;
  pubsub.subscribe("/app", [&] (const SVSPubSub::SubscriptionData&) {
    ++callbackCount;
  });

  const BootstrapTime bootstrapTime = 150;
  pubsub.insertMapping("/peer", bootstrapTime, 1, "/app/item", {});
  for (size_t round = 0; round < 5; ++round) {
    BOOST_CHECK(pubsub.processMapping("/peer", bootstrapTime, 1));
  }

  KeyChain keyChain("pib-memory:svspubsub-repeat-test",
                    "tpm-memory:svspubsub-repeat-test");
  keyChain.createIdentity("/svspubsub-repeat-test");
  Data publication("/app/item");
  const std::string payload = "one delivery";
  publication.setContent(make_span(reinterpret_cast<const uint8_t*>(payload.data()),
                                   payload.size()));
  keyChain.sign(publication);

  BOOST_CHECK(pubsub.satisfyPendingFetchFromPiggyData(publication));
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

BOOST_AUTO_TEST_CASE(SingleWorkerPreparesOffFaceAndCommitsOnFaceInOrder)
{
  DummyClientFace face;
  KeyChain keyChain("pib-memory:svspubsub-worker-thread-test",
                    "tpm-memory:svspubsub-worker-thread-test");
  keyChain.createIdentity("/svspubsub-worker-thread-test");
  auto signer = std::make_shared<ThreadRecordingDataSigner>(keyChain);
  SecurityOptions security(keyChain);
  security.dataSigner = signer;
  security.pubSigner = signer;

  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.maxPiggyDataSize = 1;
  opts.publicationPreparationWorkers = 1;
  opts.publicationPreparationQueueCapacity = 512;

  SVSPubSub pubsub("/sync/worker-thread", "/local/worker-thread", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts, security);

  const auto faceThread = std::this_thread::get_id();
  std::vector<std::thread::id> commitThreads;
  std::vector<SeqNo> committedSeqs;
  pubsub.setPreparedPublicationCommitHookForTest([&] (SeqNo seqNo) {
    commitThreads.push_back(std::this_thread::get_id());
    committedSeqs.push_back(seqNo);
  });

  constexpr size_t publicationCount = 128;
  const auto payload = makePayload(256);
  std::exception_ptr publisherError;
  std::thread publisher([&] {
    try {
      for (size_t i = 0; i < publicationCount; ++i) {
        pubsub.publishAsync(Name("/app/item").appendNumber(i), payload);
      }
    }
    catch (...) {
      publisherError = std::current_exception();
    }
  });

  runIoUntil(face, [&] {
    return pubsub.getPublicationPreparationStats().committed == publicationCount;
  });
  publisher.join();
  if (publisherError) {
    std::rethrow_exception(publisherError);
  }
  runIoUntil(face, [&] {
    return pubsub.getPublicationPreparationStats().outstanding == 0;
  });

  const auto stats = pubsub.getPublicationPreparationStats();
  BOOST_CHECK_EQUAL(stats.accepted, publicationCount);
  BOOST_CHECK_EQUAL(stats.prepared, publicationCount);
  BOOST_CHECK_EQUAL(stats.committed, publicationCount);
  BOOST_CHECK_EQUAL(stats.failed, 0);
  BOOST_CHECK_EQUAL(stats.outstanding, 0);
  BOOST_REQUIRE_EQUAL(committedSeqs.size(), publicationCount);
  for (size_t i = 0; i < committedSeqs.size(); ++i) {
    BOOST_CHECK_EQUAL(committedSeqs[i], i + 1);
  }
  BOOST_CHECK(std::all_of(commitThreads.begin(), commitThreads.end(),
                          [faceThread] (const auto& id) {
                            return id == faceThread;
                          }));

  const auto signingThreads = signer->threads();
  BOOST_REQUIRE(!signingThreads.empty());
  BOOST_CHECK(std::all_of(signingThreads.begin(), signingThreads.end(),
                          [faceThread] (const auto& id) {
                            return id != faceThread;
                          }));
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
  runIoFor(face, 20_ms);
  face.sentInterests.clear();

  MissingDataInfo missing;
  missing.nodeId = "/offline";
  missing.bootstrapTime = 400;
  missing.low = 1;
  missing.high = 2;

  pubsub.updateCallbackInternal({missing});
  runIoUntil(face, [&] { return !face.sentInterests.empty(); });
  BOOST_REQUIRE_EQUAL(face.sentInterests.size(), 1);

  runIoFor(face, 2500_ms);
  pubsub.updateCallbackInternal({missing});
  BOOST_CHECK_EQUAL(face.sentInterests.size(), 1);
}

BOOST_AUTO_TEST_CASE(ProducerCatchUpFetchesKnownPublicationsAfterLateSubscription)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.publicationFetchWindow = 4;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);
  runIoFor(face, 20_ms);
  face.sentInterests.clear();

  MissingDataInfo alreadyKnown;
  alreadyKnown.nodeId = "/producer/session";
  alreadyKnown.bootstrapTime = 500;
  alreadyKnown.low = 1;
  alreadyKnown.high = 3;

  // The state arrives before the application installs its subscription.
  pubsub.updateCallbackInternal({alreadyKnown});
  runIoFor(face, 20_ms);
  BOOST_CHECK(face.sentInterests.empty());

  std::set<SeqNo> deliveredSequences;
  pubsub.subscribeToProducerWithCatchUp(
    "/producer",
    [&] (const SVSPubSub::SubscriptionData& data) {
      deliveredSequences.insert(data.seqNo);
    },
    2);
  runIoUntil(face, [&] { return face.sentInterests.size() >= 2; });

  const auto expectedSecond =
    pubsub.getSVSync().getDataName(alreadyKnown.nodeId,
                                  alreadyKnown.bootstrapTime, 2);
  const auto expectedThird =
    pubsub.getSVSync().getDataName(alreadyKnown.nodeId,
                                  alreadyKnown.bootstrapTime, 3);
  BOOST_REQUIRE_EQUAL(face.sentInterests.size(), 2);
  const std::set<Name> fetchedNames = {
    face.sentInterests[0].getName(), face.sentInterests[1].getName()
  };
  BOOST_CHECK_EQUAL(fetchedNames.count(expectedSecond), 1);
  BOOST_CHECK_EQUAL(fetchedNames.count(expectedThird), 1);

  KeyChain keyChain("pib-memory:svspubsub-late-producer",
                    "tpm-memory:svspubsub-late-producer");
  keyChain.createIdentity("/svspubsub-test/late-producer");
  for (const auto& [seqNo, outerName] :
       std::vector<std::pair<SeqNo, Name>>{{2, expectedSecond}, {3, expectedThird}}) {
    Data inner(Name("/app/item").appendSequenceNumber(seqNo));
    const auto body = makePayload(static_cast<size_t>(seqNo));
    inner.setContent(body);
    keyChain.sign(inner);

    Data outer(outerName);
    outer.setContent(inner.wireEncode());
    outer.setContentType(ndn::tlv::Data);
    keyChain.sign(outer);
    face.receive(outer);
  }
  runIoUntil(face, [&] { return deliveredSequences.size() == 2; });
  BOOST_CHECK_EQUAL(deliveredSequences.count(2), 1);
  BOOST_CHECK_EQUAL(deliveredSequences.count(3), 1);
}

BOOST_AUTO_TEST_CASE(ProducerCatchUpDoesNotReplayExpiredKnownHistory)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub pubsub("/sync", "/local", face,
                   [] (const std::vector<MissingDataInfo>&) {},
                   opts);
  runIoFor(face, 20_ms);
  face.sentInterests.clear();

  MissingDataInfo oldState;
  oldState.nodeId = "/producer/session";
  oldState.bootstrapTime = 600;
  oldState.low = 1;
  oldState.high = 100;
  pubsub.updateCallbackInternal({oldState});
  runIoFor(face, 20_ms);

  pubsub.subscribeToProducerWithCatchUp(
    "/producer", [] (const SVSPubSub::SubscriptionData&) {}, 4, 1_ms);
  runIoFor(face, 20_ms);
  BOOST_CHECK(face.sentInterests.empty());
}

BOOST_AUTO_TEST_CASE(UnsubscribedCatchUpDoesNotReceivePendingPublication)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  SVSPubSub pubsub("/sync", "/local", face, [] (const auto&) {}, opts);
  runIoFor(face, 20_ms);
  face.sentInterests.clear();

  MissingDataInfo known;
  known.nodeId = "/producer/session";
  known.bootstrapTime = 700;
  known.low = known.high = 1;
  pubsub.updateCallbackInternal({known});
  size_t cancelledCalls = 0;
  size_t activeCalls = 0;
  const auto cancelled = pubsub.subscribeToProducerWithCatchUp(
    "/producer", [&] (const auto&) { ++cancelledCalls; }, 1);
  pubsub.subscribeToProducerWithCatchUp(
    "/producer", [&] (const auto&) { ++activeCalls; }, 1);
  runIoUntil(face, [&] { return !face.sentInterests.empty(); });
  BOOST_REQUIRE(!face.sentInterests.empty());
  pubsub.unsubscribe(cancelled);

  KeyChain keys("pib-memory:catch-up-cancellation", "tpm-memory:catch-up-cancellation");
  keys.createIdentity("/test/catch-up-cancellation");
  Data inner("/app/cancel-test");
  const auto payload = makePayload(8);
  inner.setContent(payload);
  keys.sign(inner);
  Data outer(pubsub.getSVSync().getDataName(known.nodeId, known.bootstrapTime, 1));
  outer.setContent(inner.wireEncode());
  outer.setContentType(ndn::tlv::Data);
  keys.sign(outer);
  face.receive(outer);
  runIoUntil(face, [&] { return activeCalls == 1; });
  BOOST_CHECK_EQUAL(activeCalls, 1);
  BOOST_CHECK_EQUAL(cancelledCalls, 0);
}

BOOST_AUTO_TEST_CASE(ExplicitV2PubSubProducesAndConsumesV2Mappings)
{
  DummyClientFace producerFace;
  DummyClientFace consumerFace;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.syncProtocol.version = SvsProtocolVersion::V2;
  SVSPubSub producer("/sync", "/producer", producerFace, [] (const auto&) {}, opts);
  SVSPubSub consumer("/sync", "/consumer", consumerFace, [] (const auto&) {}, opts);
  std::set<Name> observed;
  consumer.subscribeWithRegex(Regex("^<app><>*$"),
    [&] (const auto& item) { observed.insert(item.name); }, false);

  producer.publish(Name("/app/v2-mapping"), Name("/producer"));
  const auto extensions = producer.onGetExtraBlocks(VersionVector());
  BOOST_REQUIRE(!extensions.empty());
  for (const auto& extension : extensions) {
    if (extension.type() == ndn::svs::tlv::MappingData) {
      BOOST_CHECK_NO_THROW(MappingList(extension, SvsProtocolVersion::V2));
    }
  }
  consumer.onRecvExtraBlocks(extensions, VersionVector());
  BOOST_CHECK_EQUAL(observed.count(Name("/app/v2-mapping")), 1);
}

BOOST_AUTO_TEST_CASE(ExplicitV2PubSubFetchesMappingUsingV2Query)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.syncProtocol.version = SvsProtocolVersion::V2;
  SVSPubSub consumer("/sync", "/consumer", face, [] (const auto&) {}, opts);
  runIoFor(face, 20_ms);
  face.sentInterests.clear();
  std::set<Name> observed;
  consumer.subscribeWithRegex(Regex("^<app><>*$"),
    [&] (const auto& item) { observed.insert(item.name); }, false);
  consumer.updateCallbackInternal({MissingDataInfo{"/peer", 1, 1, 0, 0}});
  runIoUntil(face, [&] { return !face.sentInterests.empty(); });
  BOOST_REQUIRE(!face.sentInterests.empty());
  const auto expected = Name("/peer/sync/MAPPING").appendNumber(1).appendNumber(1);
  BOOST_REQUIRE_EQUAL(face.sentInterests.front().getName(), expected);

  MappingList mapping("/peer", SvsProtocolVersion::V2);
  mapping.pairs.push_back({0, 1, {Name("/app/v2-fetched"), {}}});
  KeyChain keys("pib-memory:v2-pubsub-mapping", "tpm-memory:v2-pubsub-mapping");
  keys.createIdentity("/test/v2-pubsub-mapping");
  Data response(expected);
  response.setContent(mapping.encode());
  keys.sign(response);
  face.receive(response);
  runIoUntil(face, [&] { return observed.count(Name("/app/v2-fetched")) == 1; });
  BOOST_CHECK_EQUAL(observed.count(Name("/app/v2-fetched")), 1);
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
  runIoFor(face, 20_ms);
  face.sentInterests.clear();

  BootstrapTime bootstrapTime = 500;
  pubsub.insertMapping("/peer", bootstrapTime, 1, "/app/item", {});
  BOOST_CHECK(pubsub.processMapping("/peer", bootstrapTime, 1));
  pubsub.fetchAll();
  runIoUntil(face, [&] { return !face.sentInterests.empty(); });
  BOOST_REQUIRE_EQUAL(face.sentInterests.size(), 1);
  BOOST_CHECK_EQUAL(face.sentInterests.back().getInterestLifetime(), 50_ms);

  runIoFor(face, 90_ms);
  BOOST_REQUIRE_GE(face.sentInterests.size(), 2);
  BOOST_CHECK_EQUAL(face.sentInterests.back().getInterestLifetime(), 100_ms);
  BOOST_CHECK_GE(pubsub.getPiggybackStats().publicationRetryActivations, 1);
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

BOOST_AUTO_TEST_CASE(KnownExtensionPrepareCommitIsAtomic)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  SVSPubSub pubsub("/sync/extension-atomic", "/local", face,
                   [] (const auto&) {}, opts);

  MappingList mapping("/peer");
  mapping.pairs.push_back({1700000000, 1, {Name("/app/item"), {}}});
  auto mixed = mapping.encode();
  mixed.push_back(makeStringBlock(ndn::svs::tlv::RepairData, "malformed"));
  mixed.encode();

  pubsub.onRecvExtraData(mixed, VersionVector());
  BOOST_CHECK_THROW(pubsub.processMapping("/peer", 1700000000, 1), std::out_of_range);

  // The next valid extension still commits, proving rejection did not poison
  // the extension parser or mapping state.
  pubsub.onRecvExtraData(mapping.encode(), VersionVector());
  BOOST_CHECK_NO_THROW(pubsub.processMapping("/peer", 1700000000, 1));

  BOOST_CHECK_NO_THROW(pubsub.onRecvExtraData(Block(0xF001), VersionVector()));
}

BOOST_AUTO_TEST_CASE(KnownExtensionsAreDistinctTopLevelBlocks)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  opts.repairRequestRepeatCount = 1;
  SVSPubSub pubsub("/sync/distinct-extensions", "/local", face,
                   [] (const auto&) {}, opts);

  pubsub.rememberRepairRequest(SVSPubSub::PublicationKey("/peer", 1700000000, 1));
  const auto extensions = pubsub.onGetExtraBlocks(VersionVector());
  BOOST_REQUIRE_EQUAL(extensions.size(), 2);
  BOOST_CHECK_EQUAL(extensions.at(0).type(), ndn::svs::tlv::MappingData);
  BOOST_CHECK_EQUAL(extensions.at(1).type(), ndn::svs::tlv::RepairData);
  extensions.at(0).parse();
  BOOST_CHECK(extensions.at(0).find(ndn::svs::tlv::RepairData) ==
              extensions.at(0).elements_end());
}

BOOST_AUTO_TEST_CASE(KnownExtensionCollectionPrepareCommitIsAtomic)
{
  DummyClientFace face;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;
  SVSPubSub pubsub("/sync/extension-collection", "/local", face,
                   [] (const auto&) {}, opts);

  MappingList mapping("/peer");
  mapping.pairs.push_back({1700000000, 1, {Name("/app/item"), {}}});
  auto validMapping = mapping.encode();
  auto malformedRepair = makeStringBlock(ndn::svs::tlv::RepairData, "malformed");

  pubsub.onRecvExtraBlocks({validMapping, malformedRepair}, VersionVector());
  BOOST_CHECK_THROW(pubsub.processMapping("/peer", 1700000000, 1), std::out_of_range);

  pubsub.onRecvExtraBlocks({validMapping}, VersionVector());
  BOOST_CHECK_NO_THROW(pubsub.processMapping("/peer", 1700000000, 1));
}

BOOST_AUTO_TEST_CASE(SegmentedPublicationFitsFinalSignedOuterBoundary)
{
  KeyChain boundaryKeyChain("pib-memory:spec113-outer-boundary",
                            "tpm-memory:spec113-outer-boundary");
  boundaryKeyChain.createIdentity("/spec113/outer-boundary");
  const auto below = makeSignedOuterPacketOfSize(boundaryKeyChain,
                                                  MAX_NDN_PACKET_SIZE - 1);
  const auto exact = makeSignedOuterPacketOfSize(boundaryKeyChain,
                                                  MAX_NDN_PACKET_SIZE);
  const auto above = makeSignedOuterPacketOfSize(boundaryKeyChain,
                                                  MAX_NDN_PACKET_SIZE + 1);
  BOOST_CHECK_EQUAL(below.wireEncode().size(), MAX_NDN_PACKET_SIZE - 1);
  BOOST_CHECK_EQUAL(exact.wireEncode().size(), MAX_NDN_PACKET_SIZE);
  BOOST_CHECK_EQUAL(above.wireEncode().size(), MAX_NDN_PACKET_SIZE + 1);
  BOOST_CHECK(SVSPubSub::isFinalPacketSizeAllowed(below.wireEncode().size()));
  BOOST_CHECK(SVSPubSub::isFinalPacketSizeAllowed(exact.wireEncode().size()));
  BOOST_CHECK(!SVSPubSub::isFinalPacketSizeAllowed(above.wireEncode().size()));

  for (const auto& applicationName : {
         Name("/short"),
         Name("/a/very/long/application/name/whose/components/exercise/the/final/wire/budget")}) {
    DummyClientFace face;
    KeyChain keyChain("pib-memory:spec112-boundary", "tpm-memory:spec112-boundary");
    keyChain.createIdentity("/spec112/a/long/certificate/identity/for/segment/signing");
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
      for (auto it = std::next(store->packets().begin(), before);
           it != store->packets().end(); ++it) {
        const auto& outer = it->second;
        BOOST_CHECK_LE(outer.wireEncode().size(), MAX_NDN_PACKET_SIZE);
        Data inner(outer.getContent().blockFromValue());
        const auto content = inner.getContent().value_bytes();
        BOOST_CHECK(!content.empty());
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
  KeyChain keyChain("pib-memory:spec112-sign-failure", "tpm-memory:spec112-sign-failure");
  keyChain.createIdentity("/spec112/signer");
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

  const auto large = makePayload(16000);
  BOOST_CHECK_THROW(pubsub.publishAsync("/app/large", large), std::runtime_error);
  runIoFor(face, 20_ms);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
  BOOST_CHECK_EQUAL(store->size(), 0);

  signer->disableFailure();
  const auto small = makePayload(64);
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/small", small), 1);
  runIoUntil(face, [&] {
    return pubsub.getSVSync().getCore().getSeqNo("/producer") == 1;
  });
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

  const auto large = makePayload(16000);
  BOOST_CHECK_THROW(pubsub.publishAsync("/app/large", large), std::runtime_error);
  runIoFor(face, 20_ms);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
  BOOST_CHECK_EQUAL(store->size(), 0);
  BOOST_REQUIRE_EQUAL(store->erasedNames().size(), 1);

  store->disableFailure();
  const auto small = makePayload(64);
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/small", small), 1);
  runIoUntil(face, [&] {
    return pubsub.getSVSync().getCore().getSeqNo("/producer") == 1;
  });
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 1);
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

  const auto small = makePayload(64);
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/first", small), 1);
  BOOST_CHECK_EQUAL(putCalls, 0);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
  BOOST_CHECK_GT(store->size(), 0);

  runIoUntil(face, [&] {
    return pubsub.getSVSync().getCore().getSeqNo("/producer") == 1;
  });
  BOOST_CHECK_EQUAL(putCalls, 1);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 1);
  BOOST_CHECK_GT(store->size(), 0);

  pubsub.getSVSync().setPreparedDataPutHookForTest({});
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/second", small), 2);
  runIoUntil(face, [&] {
    return pubsub.getSVSync().getCore().getSeqNo("/producer") == 2;
  });
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 2);
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

  const auto payload = makePayload(64);
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/one", payload), 1);
  BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/two", payload), 2);
  runIoFor(face, 20_ms);
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
  BOOST_CHECK_EQUAL(pubsub.getPreparedPublicationCountForTest("/producer"), 2);

  runIoUntil(face, [&] {
    return pubsub.getSVSync().getCore().getSeqNo("/producer") == 2;
  });
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 2);
  BOOST_CHECK_EQUAL(pubsub.getPreparedPublicationCountForTest("/producer"), 0);
  BOOST_CHECK_EQUAL(pubsub.getStagedPublicationCountForTest("/producer"), 0);
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
    BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
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
  BOOST_CHECK_EQUAL(pubsub.getSVSync().getCore().getSeqNo("/producer"), 0);
}

BOOST_AUTO_TEST_CASE(FetcherLateTerminalCallbacksAreHarmlessAfterDestruction)
{
  DummyClientFace face;
  SecurityOptions options(SecurityOptions::DEFAULT);
  size_t satisfied = 0;
  size_t nacked = 0;
  size_t timedOut = 0;
  Interest interest("/late/fetcher");
  interest.setInterestLifetime(10_ms);
  {
    Fetcher fetcher(face, options);
    fetcher.expressInterest(interest,
      [&] (const Interest&, const Data&) { ++satisfied; },
      [&] (const Interest&, const lp::Nack&) { ++nacked; },
      [&] (const Interest&) { ++timedOut; });
  }

  Data data(interest.getName());
  data.setContent(makePayload(8));
  KeyChain keyChain;
  keyChain.sign(data, signingWithSha256());
  face.receive(data);
  lp::Nack nack(interest);
  nack.setReason(lp::NackReason::NO_ROUTE);
  face.receive(nack);
  runIoFor(face, 30_ms);
  BOOST_CHECK_EQUAL(satisfied, 0);
  BOOST_CHECK_EQUAL(nacked, 0);
  BOOST_CHECK_EQUAL(timedOut, 0);
}

BOOST_AUTO_TEST_CASE(FetcherValidationCallbacksAndRetryAreHarmlessAfterDestruction)
{
  DummyClientFace face;
  auto validator = std::make_shared<DeferredValidator>();
  SecurityOptions options(SecurityOptions::DEFAULT);
  options.validator = validator;
  options.nRetriesOnValidationFail = 1;
  options.millisBeforeRetryOnValidationFail = 50;
  size_t terminalCallbacks = 0;
  Interest interest("/late/validation");
  {
    auto fetcher = std::make_unique<Fetcher>(face, options);
    fetcher->expressInterest(interest,
      [&] (const Interest&, const Data&) { ++terminalCallbacks; },
      [&] (const Interest&, const lp::Nack&) { ++terminalCallbacks; },
      [&] (const Interest&) { ++terminalCallbacks; });
    runIoFor(face, 5_ms);
    Data data(interest.getName());
    data.setContent(makePayload(8));
    KeyChain keyChain;
    keyChain.sign(data, signingWithSha256());
    face.receive(data);
    runIoFor(face, 20_ms);
    fetcher.reset();
  }
  BOOST_CHECK_NO_THROW(validator->reject());
  const auto sentBeforeRetry = face.sentInterests.size();
  runIoFor(face, 80_ms);
  BOOST_CHECK_EQUAL(face.sentInterests.size(), sentBeforeRetry);
  BOOST_CHECK_EQUAL(terminalCallbacks, 0);
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
    const auto large = makePayload(16000);
    BOOST_CHECK_EQUAL(pubsub.publishAsync("/app/staged", large), 1);
    BOOST_CHECK_GT(store->size(), 0);
    // Do not run the Face io_context: advertisement remains pending.
  }
  BOOST_CHECK_EQUAL(store->size(), 0);
}

BOOST_AUTO_TEST_CASE(InnerSegmentAssemblyRejectsMissingMalformedAndDuplicateSegments)
{
  KeyChain keyChain("pib-memory:spec112-assembly", "tpm-memory:spec112-assembly");
  keyChain.createIdentity("/spec112/assembly");
  const auto first = makePayload(4);
  const auto second = makePayload(5);
  const auto third = makePayload(6);

  std::vector<Block> valid = {
    makeInnerSegment(keyChain, "/app/item", 0, 2, first),
    makeInnerSegment(keyChain, "/app/item", 1, 2, second),
    makeInnerSegment(keyChain, "/app/item", 2, 2, third),
  };
  auto assembled = SVSPubSub::decodeInnerSegments(valid);
  BOOST_REQUIRE(assembled.has_value());
  BOOST_CHECK_EQUAL(assembled->payload.size(), first.size() + second.size() + third.size());

  BOOST_CHECK(!SVSPubSub::decodeInnerSegments({valid[0], valid[2]}).has_value());
  BOOST_CHECK(!SVSPubSub::decodeInnerSegments({valid[0], valid[0], valid[1], valid[2]}).has_value());
  BOOST_CHECK(!SVSPubSub::decodeInnerSegments({Block(ndn::tlv::Content)}).has_value());
}

BOOST_AUTO_TEST_CASE(ValidationFailureAndLateCallbackReclaimFetchStateSafely)
{
  DummyClientFace face;
  KeyChain keyChain("pib-memory:spec112-validation", "tpm-memory:spec112-validation");
  keyChain.createIdentity("/spec112/validation");
  SecurityOptions securityOptions(keyChain);
  auto validator = std::make_shared<DeferredValidator>();
  securityOptions.encapsulatedDataValidator = validator;
  SVSPubSubOptions opts;
  opts.useTimestamp = false;

  SVSPubSub::PublicationKey publication("/peer", 10, 1);
  {
    SVSPubSub pubsub("/sync", "/local", face,
                     [] (const std::vector<MissingDataInfo>&) {}, opts, securityOptions);
    pubsub.addFetchForTest(publication,
      {1, Name("/app"), [] (const SVSPubSub::SubscriptionData&) {}, false, false});

    const auto payload = makePayload(64);
    Data inner("/app/item");
    inner.setContent(payload);
    keyChain.sign(inner);
    Data outer("/peer/sync/10/1");
    outer.setContent(inner.wireEncode());
    outer.setContentType(ndn::tlv::Data);
    keyChain.sign(outer);

    pubsub.onSyncData(outer, publication);
    validator->reject();
    BOOST_CHECK(!pubsub.hasFetchForTest(publication));

    // Cleanup is idempotent: duplicate and late terminal events cannot revive state.
    pubsub.cleanUpFetch(publication);
    BOOST_CHECK(!pubsub.hasFetchForTest(publication));
  }

  // A validator callback retained past shutdown must be harmless.
  auto lateValidator = std::make_shared<DeferredValidator>();
  securityOptions.encapsulatedDataValidator = lateValidator;
  {
    SVSPubSub pubsub("/sync", "/late", face,
                     [] (const std::vector<MissingDataInfo>&) {}, opts, securityOptions);
    pubsub.addFetchForTest(publication,
      {1, Name("/app"), [] (const SVSPubSub::SubscriptionData&) {}, false, false});
    const auto payload = makePayload(8);
    Data inner("/app/late");
    inner.setContent(payload);
    keyChain.sign(inner);
    Data outer("/peer/sync/10/1");
    outer.setContent(inner.wireEncode());
    outer.setContentType(ndn::tlv::Data);
    keyChain.sign(outer);
    pubsub.onSyncData(outer, publication);
  }
  BOOST_CHECK_NO_THROW(lateValidator->succeed());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
