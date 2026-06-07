/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2025 University of California, Los Angeles
 *
 * This file is part of ndn-svs, synchronization library for distributed realtime
 * applications for NDN.
 */

#include "mapping-provider.hpp"

#include "tests/boost-test.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

#include <thread>
#include <set>

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
runIoFor(Face& face, std::chrono::milliseconds duration)
{
  auto deadline = std::chrono::steady_clock::now() + duration;
  while (std::chrono::steady_clock::now() < deadline) {
    face.getIoContext().restart();
    face.getIoContext().run_for(10ms);
    std::this_thread::sleep_for(1ms);
  }
}

BOOST_AUTO_TEST_SUITE(TestMappingProvider)

BOOST_AUTO_TEST_CASE(RangeQueryReturnsAvailableMappings)
{
  boost::asio::io_context io;
  DummyClientFace providerFace(io, {true, true});

  KeyChain keyChain("pib-memory:mapping-provider-test", "tpm-memory:mapping-provider-test");
  keyChain.createIdentity("/mapping-provider-test");
  SecurityOptions securityOptions(keyChain);

  const Name syncPrefix("/sync");
  const Name producer("/producer");
  const BootstrapTime bootstrapTime = 100;

  MappingProvider provider(syncPrefix, producer, providerFace, securityOptions);

  provider.insertMapping(producer, bootstrapTime, 1, {Name("/app/one"), {}});
  provider.insertMapping(producer, bootstrapTime, 3, {Name("/app/three"), {}});
  runIoFor(providerFace, 50ms);

  Name queryName(producer);
  queryName.append(syncPrefix)
           .append("MAPPING")
           .append(Name::Component::fromTimestamp(
             time::fromUnixTimestamp(time::seconds(bootstrapTime))))
           .append(Name::Component::fromSequenceNumber(1))
           .append(Name::Component::fromSequenceNumber(3));

  providerFace.receive(Interest(queryName));
  runIoUntil(providerFace, [&] {
    return !providerFace.sentData.empty();
  });

  BOOST_REQUIRE(!providerFace.sentData.empty());
  MappingList received(providerFace.sentData.back().getContent().blockFromValue());
  BOOST_REQUIRE_EQUAL(received.pairs.size(), 2);
  BOOST_CHECK_EQUAL(received.nodeId, producer);
  std::set<SeqNo> seqNos;
  for (const auto& entry : received.pairs)
    seqNos.insert(entry.seqNo);
  BOOST_CHECK(seqNos.count(1));
  BOOST_CHECK(seqNos.count(3));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
