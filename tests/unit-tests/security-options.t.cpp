/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2025 University of California, Los Angeles
 *
 * This file is part of ndn-svs, synchronization library for distributed realtime
 * applications for NDN.
 */

#include "security-options.hpp"

#include "tests/boost-test.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn::tests {

using namespace ndn::svs;

BOOST_AUTO_TEST_SUITE(TestSecurityOptions)

BOOST_AUTO_TEST_CASE(SignedInterestTimestampIsMonotonic)
{
  KeyChain keyChain("pib-memory:", "tpm-memory:");
  auto identity = keyChain.createIdentity("/ndn/svs/test/signer");

  KeyChainSigner signer(keyChain);
  signer.signingInfo = security::signingByIdentity(identity);

  std::optional<time::milliseconds> previous;
  for (size_t i = 0; i < 32; ++i) {
    Interest interest(Name("/ndn/svs/test/sync").appendNumber(i));
    interest.setApplicationParameters(makeStringBlock(tlv::ApplicationParameters, "state"));

    signer.sign(interest);

    BOOST_REQUIRE(interest.getSignatureInfo().has_value());
    auto timestamp = interest.getSignatureInfo()->getTime();
    BOOST_REQUIRE(timestamp.has_value());

    auto timestampMs = time::toUnixTimestamp(*timestamp);
    if (previous) {
      BOOST_CHECK_GT(timestampMs.count(), previous->count());
    }
    previous = timestampMs;
  }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
