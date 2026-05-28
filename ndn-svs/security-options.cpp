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

#include "security-options.hpp"

namespace ndn::svs {

const SecurityOptions SecurityOptions::DEFAULT{ SecurityOptions::DEFAULT_KEYCHAIN };

BaseSigner::~BaseSigner() = default;

void
KeyChainSigner::sign(Interest& interest) const
{
  auto params = signingInfo;
  auto sigInfo = params.getSignatureInfo();
  sigInfo.setTime(getFreshInterestTimestamp());
  params.setSignatureInfo(sigInfo);
  params.setSignedInterestFormat(security::SignedInterestFormat::V03);
  m_keyChain.sign(interest, params);
}

void
KeyChainSigner::sign(Data& data) const
{
  m_keyChain.sign(data, signingInfo);
}

time::system_clock::time_point
KeyChainSigner::getFreshInterestTimestamp() const
{
  std::lock_guard<std::mutex> lock(m_interestTimestampMutex);

  auto timestamp = time::system_clock::now();
  if (time::duration_cast<time::milliseconds>(timestamp - m_lastInterestTimestamp) >
      time::milliseconds(0)) {
    m_lastInterestTimestamp = timestamp;
  }
  else {
    m_lastInterestTimestamp += time::milliseconds(1);
    timestamp = m_lastInterestTimestamp;
  }

  return timestamp;
}

SecurityOptions::SecurityOptions(KeyChain& keyChain)
  : interestSigner(std::make_shared<KeyChainSigner>(keyChain))
  , dataSigner(std::make_shared<KeyChainSigner>(keyChain))
  , pubSigner(std::make_shared<KeyChainSigner>(keyChain))
{
  interestSigner->signingInfo.setSignedInterestFormat(security::SignedInterestFormat::V03);
}

} // namespace ndn::svs
