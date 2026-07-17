/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
#include "sync-protocol.hpp"

#include <cmath>
#include <chrono>
#include <set>

#ifdef NDN_SVS_COMPRESSION
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filter/lzma.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#endif

namespace ndn::svs {

ResolvedSyncProtocolOptions
SyncProtocolOptions::resolve() const
{
  if (periodicJitter < 0.0 || periodicJitter > 1.0) {
    NDN_THROW(std::invalid_argument("SVS periodic jitter must be in [0,1]"));
  }

  ResolvedSyncProtocolOptions resolved;
  resolved.version = version;
  resolved.bootstrapTime = bootstrapTime;
  resolved.periodicJitter = periodicJitter;
  if (version == SvsProtocolVersion::V2) {
    resolved.syncInterestLifetime = syncInterestLifetime.value_or(1_ms);
    resolved.suppressionPeriod = suppressionPeriod.value_or(500_ms);
  }
  else if (version == SvsProtocolVersion::V3) {
    resolved.syncInterestLifetime = syncInterestLifetime.value_or(1_s);
    resolved.suppressionPeriod = suppressionPeriod.value_or(200_ms);
  }
  else {
    NDN_THROW(std::invalid_argument("unsupported SVS protocol version"));
  }
  resolved.periodicTimeout = periodicTimeout.value_or(30_s);

  if (resolved.syncInterestLifetime <= 0_ms || resolved.suppressionPeriod < 0_ms ||
      resolved.periodicTimeout <= 0_ms) {
    NDN_THROW(std::invalid_argument("SVS protocol timers are out of range"));
  }
  if (resolved.bootstrapTime) {
    const auto now = static_cast<BootstrapTime>(
      time::toUnixTimestamp<time::seconds>(time::system_clock::now()).count());
    if (*resolved.bootstrapTime > now + 86400) {
      NDN_THROW(std::invalid_argument("SVS bootstrap time is too far in the future"));
    }
  }
  return resolved;
}

Name
SyncProtocolCodec::makeSyncName(const Name& groupPrefix, SvsProtocolVersion version)
{
  return Name(groupPrefix).appendVersion(static_cast<uint64_t>(version));
}

Interest
SyncProtocolCodec::encode(const Name& groupPrefix,
                          const VersionVector& stateVector,
                          const std::vector<Block>& extensions,
                          const ResolvedSyncProtocolOptions& options,
                          const DataSigner& signData)
{
  const auto syncName = makeSyncName(groupPrefix, options.version);
  if (extensions.size() > MAX_EXTENSION_BLOCKS) {
    NDN_THROW(Error("too many SVS extension blocks"));
  }
  std::set<uint32_t> knownExtensionTypes;
  for (const auto& extension : extensions) {
    if ((extension.type() == tlv::MappingData || extension.type() == tlv::RepairData) &&
        !knownExtensionTypes.insert(extension.type()).second) {
      NDN_THROW(Error("duplicate known SVS extension"));
    }
    if (extension.type() == tlv::StateVector || extension.type() == ndn::tlv::Data) {
      NDN_THROW(Error("extension collides with SVS core envelope"));
    }
  }
  ndn::encoding::EncodingBuffer encoder;
  size_t length = 0;

  for (auto it = extensions.rbegin(); it != extensions.rend(); ++it) {
    length += ndn::encoding::prependBlock(encoder, *it);
  }

  if (options.version == SvsProtocolVersion::V3) {
    Data stateData(syncName);
    stateData.setContent(stateVector.encode());
    if (!signData) {
      NDN_THROW(std::invalid_argument("SVS V3 requires a Data signer"));
    }
    signData(stateData);
    length += ndn::encoding::prependBlock(encoder, stateData.wireEncode());
  }
  else {
    length += ndn::encoding::prependBlock(encoder, stateVector.encodeV2());
  }

  encoder.prependVarNumber(length);
  encoder.prependVarNumber(ndn::tlv::ApplicationParameters);

  Interest interest(syncName);
  auto parameters = encoder.block();
#ifdef NDN_SVS_COMPRESSION
  if (options.version == SvsProtocolVersion::V2) {
    parameters.encode();
    boost::iostreams::filtering_istreambuf input;
    input.push(boost::iostreams::lzma_compressor());
    input.push(boost::iostreams::array_source(
      reinterpret_cast<const char*>(parameters.data()), parameters.size()));
    ndn::OBufferStream compressed;
    boost::iostreams::copy(input, compressed);
    parameters = Block(tlv::LzmaBlock, compressed.buf());
    parameters.encode();
  }
#endif
  interest.setApplicationParameters(parameters);
  interest.setInterestLifetime(options.syncInterestLifetime);
  return interest;
}

DecodedSyncEnvelope
SyncProtocolCodec::decode(const Interest& interest,
                          const Name& groupPrefix,
                          SvsProtocolVersion version,
                          bool decodeSemanticState)
{
  const auto expectedPrefix = makeSyncName(groupPrefix, version);
  if (interest.getName().size() != expectedPrefix.size() + 1 ||
      interest.getName().getPrefix(expectedPrefix.size()) != expectedPrefix ||
      !interest.getName().at(-1).isParametersSha256Digest() ||
      !interest.isParametersDigestValid()) {
    NDN_THROW(ndn::tlv::Error("SVS Sync Interest name or parameters digest"));
  }
  if (!interest.hasApplicationParameters()) {
    NDN_THROW(ndn::tlv::Error("missing SVS ApplicationParameters"));
  }

  auto params = interest.getApplicationParameters();
  params.parse();
#ifdef NDN_SVS_COMPRESSION
  if (version == SvsProtocolVersion::V2 &&
      params.find(tlv::LzmaBlock) != params.elements_end()) {
    const auto compressed = params.get(tlv::LzmaBlock);
    boost::iostreams::filtering_istreambuf input;
    input.push(boost::iostreams::lzma_decompressor());
    input.push(boost::iostreams::array_source(
      reinterpret_cast<const char*>(compressed.value()), compressed.value_size()));
    ndn::OBufferStream decompressed;
    boost::iostreams::copy(input, decompressed);
    auto [ok, decoded] = Block::fromBuffer(decompressed.buf());
    if (!ok || decoded.type() != ndn::tlv::ApplicationParameters) {
      NDN_THROW(Error("invalid compressed SVS V2 parameters"));
    }
    params = std::move(decoded);
    params.parse();
  }
#endif
  if (params.elements().empty()) {
    NDN_THROW(ndn::tlv::Error("empty SVS ApplicationParameters"));
  }

  DecodedSyncEnvelope decoded;
  std::set<uint32_t> knownExtensionTypes;
  auto first = params.elements_begin();
  if (version == SvsProtocolVersion::V3) {
    if (first->type() != ndn::tlv::Data) {
      NDN_THROW(ndn::tlv::Error("SVS V3 State Vector Data", first->type()));
    }
    Data stateData(*first);
    if (stateData.getName() != expectedPrefix || !stateData.getSignatureValue().isValid()) {
      NDN_THROW(ndn::tlv::Error("invalid SVS V3 State Vector Data"));
    }
    const auto stateBlock = stateData.getContent().blockFromValue();
    if (stateBlock.type() != tlv::StateVector) {
      NDN_THROW(ndn::tlv::Error("SVS V3 StateVector Content", stateBlock.type()));
    }
    decoded.stateVectorData = std::move(stateData);
    if (decodeSemanticState) {
      decoded.stateVector = decodeStateVector(decoded, version);
      decoded.stateVectorDecoded = true;
    }
  }
  else {
    if (first->type() != tlv::StateVector) {
      NDN_THROW(ndn::tlv::Error("SVS V2 StateVector", first->type()));
    }
    decoded.stateVector = VersionVector::decodeV2(*first);
    decoded.stateVectorDecoded = true;
  }

  for (++first; first != params.elements_end(); ++first) {
    if (decoded.extensions.size() >= MAX_EXTENSION_BLOCKS) {
      NDN_THROW(Error("too many SVS extension blocks"));
    }
    if (first->type() == tlv::StateVector || first->type() == ndn::tlv::Data) {
      NDN_THROW(Error("duplicate SVS core envelope"));
    }
    if ((first->type() == tlv::MappingData || first->type() == tlv::RepairData) &&
        !knownExtensionTypes.insert(first->type()).second) {
      NDN_THROW(Error("duplicate known SVS extension"));
    }
    decoded.extensions.push_back(*first);
  }
  return decoded;
}

VersionVector
SyncProtocolCodec::decodeStateVector(const DecodedSyncEnvelope& envelope,
                                     SvsProtocolVersion version)
{
  if (version == SvsProtocolVersion::V2) {
    if (!envelope.stateVectorDecoded) {
      NDN_THROW(Error("SVS V2 StateVector was not decoded"));
    }
    return envelope.stateVector;
  }
  if (version != SvsProtocolVersion::V3 || !envelope.stateVectorData) {
    NDN_THROW(Error("missing SVS V3 State Vector Data"));
  }
  const auto stateBlock = envelope.stateVectorData->getContent().blockFromValue();
  if (stateBlock.type() != tlv::StateVector) {
    NDN_THROW(ndn::tlv::Error("SVS V3 StateVector Content", stateBlock.type()));
  }
  return VersionVector(stateBlock);
}

} // namespace ndn::svs
