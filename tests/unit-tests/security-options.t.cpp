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

BOOST_AUTO_TEST_CASE(KeyChainSignerSignsV03Interests)
{
  KeyChain keyChain("pib-memory:security-options-test", "tpm-memory:security-options-test");
  auto identity = keyChain.createIdentity("/ndn/svs/test/signer");

  KeyChainSigner signer(keyChain);
  signer.signingInfo = security::signingByIdentity(identity);

  Interest first("/ndn/svs/test/sync/1");
  first.setApplicationParameters(makeStringBlock(tlv::ApplicationParameters, "state"));
  signer.sign(first);

  BOOST_CHECK(first.isSigned());
  BOOST_REQUIRE(first.getSignatureInfo().has_value());
  BOOST_CHECK(first.getSignatureInfo()->getNonce().has_value());
  BOOST_CHECK(first.getSignatureInfo()->getTime().has_value());
  BOOST_CHECK(first.getSignatureInfo()->getSeqNum().has_value() == false);

  Interest second("/ndn/svs/test/sync/2");
  second.setApplicationParameters(makeStringBlock(tlv::ApplicationParameters, "state"));
  signer.sign(second);

  BOOST_CHECK(second.isSigned());
  BOOST_REQUIRE(second.getSignatureInfo().has_value());
  BOOST_CHECK(second.getSignatureInfo()->getNonce().has_value());
  BOOST_CHECK(second.getSignatureInfo()->getTime().has_value());
  BOOST_CHECK_GT(*second.getSignatureInfo()->getTime(), *first.getSignatureInfo()->getTime());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn::tests
