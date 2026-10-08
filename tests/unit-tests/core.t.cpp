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
#include "mapping-provider.hpp"
#include "svspubsub.hpp"
#include "svsync.hpp"
#include "tlv.hpp"

#include "tests/boost-test.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>

#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>

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
  }
}

class CoreFixture
{
protected:
  CoreFixture()
    : m_syncPrefix("/ndn/test")
    , m_core(
        m_face,
        m_syncPrefix,
        [] (auto&&...) {},
        SecurityOptions::DEFAULT,
        SVSyncCore::EMPTY_NODE_ID)
  {
  }

protected:
  DummyClientFace m_face;
  Name m_syncPrefix;
  SVSyncCore m_core;
};

class PublicationValidator : public BaseValidator
{
public:
  bool rejectLast = false;
  bool rejectLastOnce = false;
  bool defer = false;
  size_t validated = 0;
  std::vector<std::function<void()>> pending;

  void
  validate(const Data& data,
           const security::DataValidationSuccessCallback& success,
           const security::DataValidationFailureCallback& failure) override
  {
    ++validated;
    if ((rejectLast || rejectLastOnce) && data.getName()[-1].isSegment() &&
        data.getName()[-1].toSegment() == 1) {
      rejectLastOnce = false;
      failure(data, security::ValidationError::INVALID_SIGNATURE);
    }
    else if (defer)
      pending.push_back([data, success] { success(data); });
    else
      success(data);
  }
};

BOOST_AUTO_TEST_SUITE(TestCore)

BOOST_FIXTURE_TEST_CASE(MergeStateVector, CoreFixture)
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

  {
    VersionVector local;
    local.set("one", 100, 2);
    local.set("local-only", 700, 7);

    VersionVector remote;
    remote.set("one", 100, 5);
    remote.set("two", 200, 1);

    m_core.getState() = local;
    auto result = m_core.mergeStateVector(remote);

    BOOST_CHECK(result.myVectorNew);
    BOOST_CHECK(result.otherVectorNew);
    BOOST_CHECK_EQUAL(m_core.getState().get("one"), 5);
    BOOST_CHECK_EQUAL(m_core.getState().get("two"), 1);
    BOOST_CHECK_EQUAL(m_core.getState().get("local-only"), 7);

    BOOST_REQUIRE_EQUAL(result.missingInfo.size(), 2);
    BOOST_CHECK_EQUAL(result.missingInfo[0].nodeId, "one");
    BOOST_CHECK_EQUAL(result.missingInfo[0].bootstrapTime, 100);
    BOOST_CHECK_EQUAL(result.missingInfo[0].low, 3);
    BOOST_CHECK_EQUAL(result.missingInfo[0].high, 5);
    BOOST_CHECK_EQUAL(result.missingInfo[1].nodeId, "two");
    BOOST_CHECK_EQUAL(result.missingInfo[1].bootstrapTime, 200);
    BOOST_CHECK_EQUAL(result.missingInfo[1].low, 1);
    BOOST_CHECK_EQUAL(result.missingInfo[1].high, 1);
  }
}

BOOST_AUTO_TEST_CASE(SyncInterestContainsDataSignedByConfiguredIdentity)
{
  const Name syncPrefix("/ndn/test");
  DummyClientFace face;
  KeyChain keyChain("pib-memory:core-signing", "tpm-memory:core-signing");
  auto identity = keyChain.createIdentity("/core/signer");
  SecurityOptions options(keyChain);
  options.dataSigner->signingInfo = security::signingByIdentity("/core/signer");
  SVSyncCore core(face, syncPrefix, [] (auto&&...) {}, options);
  core.sendInitialInterest();
  runIoUntil(face, [&] {
    return std::any_of(
      face.sentInterests.begin(), face.sentInterests.end(), [&] (const Interest& interest) {
        return syncPrefix.isPrefixOf(interest.getName());
      });
  });

  const auto found = std::find_if(
    face.sentInterests.begin(), face.sentInterests.end(), [&] (const Interest& interest) {
      return syncPrefix.isPrefixOf(interest.getName());
    });
  BOOST_REQUIRE(found != face.sentInterests.end());
  BOOST_REQUIRE_GE(found->getName().size(), syncPrefix.size() + 2);
  BOOST_CHECK(found->getName().at(syncPrefix.size()).isVersion());
  BOOST_CHECK_EQUAL(found->getName().at(syncPrefix.size()).toVersion(), 3);
  BOOST_CHECK_EQUAL(found->getInterestLifetime(), 1_s);

  auto params = found->getApplicationParameters();
  params.parse();
  BOOST_REQUIRE(!params.elements().empty());
  BOOST_CHECK_EQUAL(params.elements().front().type(), ndn::tlv::Data);
  Data data(params.elements().front());
  BOOST_CHECK_EQUAL(data.getName(), Name(syncPrefix).appendVersion(3));
  BOOST_CHECK(security::verifySignature(data, identity.getDefaultKey()));
}

BOOST_AUTO_TEST_CASE(PublicationNameIncludesSessionAndTypedSequence)
{
  DummyClientFace face;
  SVSync sync(
    "/group",
    "/node",
    face,
    [] (const auto&) {},
    SecurityOptions::DEFAULT,
    SVSync::DEFAULT_DATASTORE,
    1700000000);

  const auto name = sync.getDataName("/node", 1700000000, 7);
  BOOST_REQUIRE_EQUAL(name.size(), 4);
  BOOST_CHECK_EQUAL(name.getPrefix(2), "/node/group");
  BOOST_CHECK(name.at(2).isTimestamp());
  BOOST_CHECK_EQUAL(name.at(2).toNumber(), 1700000000000ULL);
  BOOST_CHECK(name.at(3).isSequenceNumber());
  BOOST_CHECK_EQUAL(name.at(3).toSequenceNumber(), 7);
  BOOST_CHECK(name != sync.getDataName("/node", 1700000001, 7));
}

BOOST_AUTO_TEST_CASE(MappingDataUsesV3WireFormat)
{
  MappingList list("/node");
  list.pairs.push_back({7, {"/app/data", {}}});

  auto encoded = list.encode();
  encoded.parse();
  BOOST_REQUIRE_EQUAL(encoded.type(), ndn::svs::tlv::MappingData);
  BOOST_REQUIRE_EQUAL(encoded.elements_size(), 2);
  auto entry = encoded.elements().at(1);
  entry.parse();
  BOOST_REQUIRE_EQUAL(entry.type(), ndn::svs::tlv::MappingEntry);
  BOOST_REQUIRE_EQUAL(entry.elements_size(), 2);
  BOOST_CHECK_EQUAL(entry.elements().at(0).type(), ndn::svs::tlv::MappingSeqNo);
  BOOST_CHECK_EQUAL(ndn::encoding::readNonNegativeInteger(entry.elements().at(0)), 7);
  BOOST_CHECK_EQUAL(entry.elements().at(1).type(), ndn::tlv::Name);

  MappingList decoded(encoded);
  BOOST_REQUIRE_EQUAL(decoded.pairs.size(), 1);
  BOOST_CHECK_EQUAL(decoded.pairs.front().first, 7);
  BOOST_CHECK_EQUAL(decoded.pairs.front().second.first, "/app/data");
}

BOOST_AUTO_TEST_CASE(ThreeNodesRecoverLostSyncUpdateAndRebootstrap)
{
  boost::asio::io_context io;
  DummyClientFace::Options options;
  options.enableRegistrationReply = true;
  std::array<std::unique_ptr<DummyClientFace>, 3> faces;
  std::array<std::unique_ptr<SVSyncCore>, 3> cores;
  const std::array<Name, 3> names{{Name("/a"), Name("/b"), Name("/c")}};
  bool drop = false;
  for (size_t i = 0; i < faces.size(); ++i)
    faces[i] = std::make_unique<DummyClientFace>(io, options);
  for (size_t i = 0; i < faces.size(); ++i) {
    faces[i]->onSendInterest.connect([&, i] (const Interest& interest) {
      if (!Name("/group/v=3").isPrefixOf(interest.getName()))
        return;
      for (size_t j = 0; j < faces.size(); ++j) {
        if (j != i && !(drop && i == 0 && j == 2))
          faces[j]->receive(interest);
      }
    });
    cores[i] = std::make_unique<SVSyncCore>(
      *faces[i], "/group", [] (const auto&) {}, SecurityOptions::DEFAULT, names[i], 100);
    for (size_t j = 0; j < names.size(); ++j)
      cores[i]->getState().set(names[j], 100, 10 + j);
    cores[i]->retxSyncInterest(false);
  }
  io.run_for(std::chrono::milliseconds(80));
  io.restart();
  drop = true;
  cores[0]->updateSeqNo(11);
  runIoUntil(*faces[1], [&] { return cores[1]->getState().get("/a", 100) == 11; });
  BOOST_CHECK_EQUAL(cores[1]->getState().get("/a", 100), 11);
  BOOST_CHECK_EQUAL(cores[2]->getState().get("/a", 100), 10);
  cores[0]->retxSyncInterest(false, 50);
  drop = false;
  runIoUntil(*faces[2], [&] { return cores[2]->getState().get("/a", 100) == 11; });
  BOOST_CHECK_EQUAL(cores[2]->getState().get("/a", 100), 11);
  cores[0].reset();
  cores[0] = std::make_unique<SVSyncCore>(
    *faces[0], "/group", [] (const auto&) {}, SecurityOptions::DEFAULT, "/a", 101);
  cores[1]->retxSyncInterest(false, 50);
  cores[2]->retxSyncInterest(false, 50);
  cores[0]->updateSeqNo(1);
  runIoUntil(*faces[0], [&] {
    return std::all_of(cores.begin(), cores.end(), [] (const auto& core) {
      return core->getState().get("/a", 100) == 11 && core->getState().get("/a", 101) == 1;
    });
  });
  for (const auto& core : cores) {
    BOOST_CHECK_EQUAL(core->getState().get("/a", 100), 11);
    BOOST_CHECK_EQUAL(core->getState().get("/a", 101), 1);
  }
  for (const auto& face : faces)
    BOOST_CHECK(std::none_of(face->sentData.begin(), face->sentData.end(), [] (const Data& data) {
      return Name("/group").isPrefixOf(data.getName());
    }));
}

BOOST_AUTO_TEST_CASE(SegmentsAreValidatedAndDeliveredOnce)
{
  for (int mode : {0, 1, 2, 3, 4, 5}) {
    const bool reject = mode == 1 || mode == 2 || mode == 5;
    boost::asio::io_context io;
    DummyClientFace::Options faceOptions;
    faceOptions.enableRegistrationReply = true;
    DummyClientFace producer(io, faceOptions), consumer(io, faceOptions);
    producer.linkTo(consumer);
    SVSPubSubOptions options;
    options.bootstrapTime = 100;
    SVSPubSub source("/group", "/node", producer, [] (const auto&) {}, options);
    auto outer = std::make_shared<PublicationValidator>();
    auto inner = std::make_shared<PublicationValidator>();
    outer->rejectLast = mode == 1;
    inner->rejectLast = mode == 2 || mode == 5;
    inner->rejectLastOnce = mode == 4;
    inner->defer = mode == 3;
    SecurityOptions security = SecurityOptions::DEFAULT;
    security.validator = outer;
    security.encapsulatedDataValidator = inner;
    security.nRetriesOnValidationFail = mode >= 4 ? 1 : 0;
    security.millisBeforeRetryOnValidationFail = 10;
    options.bootstrapTime = 200;
    size_t errors = 0;
    options.onFetchError = [&] (const Name& name) {
      BOOST_CHECK_EQUAL(name, source.getSVSync().getDataName("/alias", 100, 1));
      ++errors;
    };
    SVSPubSub target("/group", "/reader", consumer, [] (const auto&) {}, options, security);
    std::vector<uint8_t> payload(SVSPubSub::MAX_DATA_SIZE * 2, 42);
    size_t blobs = 0;
    std::map<uint64_t, size_t> segments;
    std::map<uint64_t, size_t> secondSubscriber;
    target.subscribeToProducer("/alias", [&] (const auto& data) {
      BOOST_CHECK_EQUAL_COLLECTIONS(
        data.data.begin(), data.data.end(), payload.begin(), payload.end());
      ++blobs;
    });
    target.subscribeToProducer(
      "/alias",
      [&] (const auto& data) {
        BOOST_REQUIRE(data.packet);
        BOOST_CHECK_EQUAL(data.packet->getFinalBlock()->toSegment(), 1);
        ++segments[data.packet->getName()[-1].toSegment()];
      },
      false,
      true);
    target.subscribeToProducer(
      "/alias",
      [&] (const auto& data) { ++secondSubscriber[data.packet->getName()[-1].toSegment()]; },
      false,
      true);
    io.run_for(std::chrono::milliseconds(150));
    io.restart();
    source.publish("/app/segmented", payload, "/alias", 0_ms);
    io.run_for(std::chrono::milliseconds(600));
    if (mode == 3) {
      BOOST_CHECK_EQUAL(blobs, 0);
      for (int step = 0; step < 3; ++step) {
        auto pending = std::move(inner->pending);
        inner->pending.clear();
        for (auto it = pending.rbegin(); it != pending.rend(); ++it)
          (*it)();
        io.restart();
        io.run_for(std::chrono::milliseconds(100));
      }
    }
    BOOST_CHECK_EQUAL(blobs, reject ? 0 : 1);
    BOOST_CHECK_EQUAL(errors, mode == 5 ? 2 : (reject || mode == 4 ? 1 : 0));
    BOOST_CHECK_EQUAL(segments.size(), reject ? 1 : 2);
    BOOST_CHECK(segments == secondSubscriber);
    for (const auto& [segment, count] : segments)
      BOOST_CHECK_EQUAL(count, 1);
    BOOST_CHECK_GE(outer->validated, 2);
    BOOST_CHECK_EQUAL(inner->validated, mode == 1 ? 1 : mode >= 4 ? 4 : 2);
  }
}

BOOST_AUTO_TEST_CASE(RegexSubscriptionsUseNamesAndExistingFetchPaths)
{
  for (bool producerSubscription : {false, true}) {
    for (bool segmented : {false, true}) {
      boost::asio::io_context io;
      DummyClientFace::Options faceOptions;
      faceOptions.enableRegistrationReply = true;
      DummyClientFace producer(io, faceOptions), consumer(io, faceOptions);
      producer.linkTo(consumer);
      SVSPubSubOptions options;
      options.bootstrapTime = 100;
      SVSPubSub source("/group", "/node", producer, [] (const auto&) {}, options);
      options.bootstrapTime = 200;
      SVSPubSub target("/group", "/reader", consumer, [] (const auto&) {}, options);
      size_t blobs = 0, packets = 0, prefixes = 0;
      const std::vector<uint8_t> payload(segmented ? 16000 : 3, 42);
      auto handle =
        target.subscribeWithRegex(Regex("^<app><camera-[0-9]+>$"), [&] (const auto& item) {
          ++blobs;
          BOOST_CHECK_EQUAL(item.name, "/app/camera-1");
          BOOST_CHECK_EQUAL_COLLECTIONS(
            item.data.begin(), item.data.end(), payload.begin(), payload.end());
        });
      auto packetHandle = target.subscribeWithRegex(
        Regex("^<app><camera-[0-9]+>$"),
        [&] (const auto& item) {
          ++packets;
          BOOST_REQUIRE(item.packet.has_value());
          BOOST_CHECK(Name("/app/camera-1").isPrefixOf(item.packet->getName()));
        },
        true);
      target.subscribe("/app/camera-1", [&] (const auto&) { ++prefixes; });
      if (producerSubscription)
        target.subscribeToProducer("/node", [] (const auto&) {});
      io.run_for(std::chrono::milliseconds(20));
      io.restart();
      source.publish("/app/camera-1", payload);
      source.publish("/app/other", payload);
      io.run_for(std::chrono::milliseconds(150));
      BOOST_CHECK_EQUAL(blobs, 1);
      BOOST_CHECK_GE(packets, 1);
      BOOST_CHECK_EQUAL(prefixes, 1);
      const auto before = packets;
      target.unsubscribe(handle);
      target.unsubscribe(packetHandle);
      io.restart();
      source.publish("/app/camera-1", payload);
      io.run_for(std::chrono::milliseconds(150));
      BOOST_CHECK_EQUAL(blobs, 1);
      BOOST_CHECK_EQUAL(packets, before);
      BOOST_CHECK_EQUAL(prefixes, 2);
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
