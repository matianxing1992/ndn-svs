/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
#ifndef NDN_SVS_SYNC_PROTOCOL_HPP
#define NDN_SVS_SYNC_PROTOCOL_HPP

#include "security-options.hpp"
#include "tlv.hpp"
#include "version-vector.hpp"

#include <optional>
#include <vector>

namespace ndn::svs {

/// @brief Wire protocol version; only version 3 is supported.
enum class SvsProtocolVersion : uint8_t
{
  V3 = 3,
};

/**
 * @brief Effective options returned by SyncProtocolOptions::resolve().
 *
 * Public value type used by SVSyncCore::getProtocolOptions() and the codec.
 * "Resolved" means timer defaults have been filled in and ranges checked;
 * an absent bootstrapTime is still chosen by the core at construction.
 */
struct ResolvedSyncProtocolOptions
{
  /// Supported wire version.
  SvsProtocolVersion version = SvsProtocolVersion::V3;
  /// Optional session start time in Unix seconds, not a millisecond timestamp.
  std::optional<BootstrapTime> bootstrapTime;
  /// Lifetime of each outgoing Sync Interest.
  time::milliseconds syncInterestLifetime = 1_s;
  /// Maximum delay used for suppression replies.
  time::milliseconds suppressionPeriod = 200_ms;
  /// Base interval between periodic Sync Interests.
  time::milliseconds periodicTimeout = 30_s;
  /// Fractional jitter applied to the periodic interval, in [0, 1].
  double periodicJitter = 0.1;
};

/**
 * @brief Public configuration accepted by sync and Pub/Sub constructors.
 *
 * Unset timers select 1 s Interest lifetime, 200 ms suppression and 30 s
 * periodic interval. An unset bootstrapTime selects the current Unix second
 * when SVSyncCore is constructed.
 */
struct SyncProtocolOptions
{
  /// Supported wire version.
  SvsProtocolVersion version = SvsProtocolVersion::V3;
  /// Optional session start time in Unix seconds.
  std::optional<BootstrapTime> bootstrapTime;
  /// Positive Interest lifetime; nullopt selects the default.
  std::optional<time::milliseconds> syncInterestLifetime;
  /// Non-negative suppression interval; nullopt selects the default.
  std::optional<time::milliseconds> suppressionPeriod;
  /// Positive periodic interval; nullopt selects the default.
  std::optional<time::milliseconds> periodicTimeout;
  /// Fractional jitter in [0, 1].
  double periodicJitter = 0.1;

  /// @brief Fill timer defaults and check version, timer and bootstrap-time ranges.
  /// @throws std::invalid_argument if an option is outside its supported range.
  ResolvedSyncProtocolOptions resolve() const;
};

/**
 * @brief Structurally decoded Sync Interest, returned by SyncProtocolCodec.
 *
 * This public codec result retains the signed Data carried in ApplicationParameters
 * so a validator can check it before semantic state-vector decoding. Successful
 * structural decoding does not verify the signature or authorize state updates.
 */
struct DecodedSyncEnvelope
{
  /// Semantic vector; usable only when stateVectorDecoded is true.
  VersionVector stateVector;
  /// Whether semantic decoding was requested and completed.
  bool stateVectorDecoded = false;
  /// Embedded signed Data retained for validation and deferred vector decoding.
  std::optional<Data> stateVectorData;
};

/// @brief Low-level wire codec; callers are responsible for signature validation.
class SyncProtocolCodec
{
public:
  /// @brief Codec structure or payload error; malformed TLVs may also throw ndn::tlv::Error.
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  /// @brief Callback that signs the embedded state-vector Data in place.
  using DataSigner = std::function<void(Data&)>;

  /// @brief Append the typed version component to the sync group prefix.
  static Name makeSyncName(const Name& groupPrefix, SvsProtocolVersion version);

  /// @brief Wrap the vector in signed Data and place it in a Sync Interest.
  static Interest encode(const Name& groupPrefix,
                         const VersionVector& stateVector,
                         const ResolvedSyncProtocolOptions& options,
                         const DataSigner& signData);

  /// @brief Check name/digest and packet structure, optionally decode the vector.
  /// @note Does not cryptographically validate the embedded Data.
  static DecodedSyncEnvelope decode(const Interest& interest,
                                    const Name& groupPrefix,
                                    SvsProtocolVersion version,
                                    bool decodeSemanticState = true);

  /// @brief Decode the vector from retained Data, after caller-controlled validation.
  static VersionVector decodeStateVector(const DecodedSyncEnvelope& envelope,
                                         SvsProtocolVersion version);
};

} // namespace ndn::svs

#endif // NDN_SVS_SYNC_PROTOCOL_HPP
