use super::{Protocol, rate_limiter::Quota};
use std::num::NonZeroU64;
use std::{
    fmt::{Debug, Display},
    str::FromStr,
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// Auxiliary struct to aid on configuration parsing.
///
/// A protocol's quota is specified as `protocol_name:tokens/time_in_seconds`.
#[derive(Debug, PartialEq, Eq)]
struct ProtocolQuota {
    protocol: Protocol,
    quota: Quota,
}

impl Display for ProtocolQuota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}/{}",
            self.protocol.as_ref(),
            self.quota.max_tokens,
            self.quota.replenish_all_every.as_secs()
        )
    }
}

impl FromStr for ProtocolQuota {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (protocol_str, quota_str) = s
            .split_once(':')
            .ok_or("Missing ':' from quota definition.")?;
        let protocol = protocol_str
            .parse()
            .map_err(|_parse_err| "Wrong protocol representation in quota")?;
        let (tokens_str, time_str) = quota_str
            .split_once('/')
            .ok_or("Quota should be defined as \"n/t\" (t in seconds). Missing '/' from quota.")?;
        let tokens = tokens_str
            .parse()
            .map_err(|_| "Failed to parse tokens from quota.")?;
        let seconds = time_str
            .parse::<u64>()
            .map_err(|_| "Failed to parse time in seconds from quota.")?;
        Ok(ProtocolQuota {
            protocol,
            quota: Quota {
                replenish_all_every: Duration::from_secs(seconds),
                max_tokens: tokens,
            },
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
pub struct OutboundRateLimiterConfig(pub RateLimiterConfig);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
pub struct InboundRateLimiterConfig(pub RateLimiterConfig);

impl FromStr for OutboundRateLimiterConfig {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RateLimiterConfig::from_str(s).map(Self)
    }
}

impl FromStr for InboundRateLimiterConfig {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RateLimiterConfig::from_str(s).map(Self)
    }
}

/// Configurations for the rate limiter.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimiterConfig {
    pub(super) ping_quota: Quota,
    pub(super) meta_data_quota: Quota,
    pub(super) status_quota: Quota,
    pub(super) goodbye_quota: Quota,
    pub(super) blocks_by_range_quota: Quota,
    pub(super) blocks_by_root_quota: Quota,
    pub(super) blobs_by_range_quota: Quota,
    pub(super) blobs_by_root_quota: Quota,
    pub(super) data_columns_by_root_quota: Quota,
    pub(super) data_columns_by_range_quota: Quota,
    pub(super) light_client_bootstrap_quota: Quota,
    pub(super) light_client_optimistic_update_quota: Quota,
    pub(super) light_client_finality_update_quota: Quota,
    pub(super) light_client_updates_by_range_quota: Quota,
}

impl RateLimiterConfig {
    pub const DEFAULT_PING_QUOTA: Quota = Quota::n_every(NonZeroU64::new(2).unwrap(), 10);
    pub const DEFAULT_META_DATA_QUOTA: Quota = Quota::n_every(NonZeroU64::new(2).unwrap(), 5);
    pub const DEFAULT_STATUS_QUOTA: Quota = Quota::n_every(NonZeroU64::new(5).unwrap(), 15);
    pub const DEFAULT_GOODBYE_QUOTA: Quota = Quota::one_every(10);
    // The number is chosen to balance between upload bandwidth required to serve
    // blocks and a decent syncing rate for honest nodes. Malicious nodes would need to
    // spread out their requests over the time window to max out bandwidth on the server.
    pub const DEFAULT_BLOCKS_BY_RANGE_QUOTA: Quota =
        Quota::n_every(NonZeroU64::new(128).unwrap(), 10);
    pub const DEFAULT_BLOCKS_BY_ROOT_QUOTA: Quota =
        Quota::n_every(NonZeroU64::new(128).unwrap(), 10);
    // `DEFAULT_BLOCKS_BY_RANGE_QUOTA` * (target + 1) to account for high usage
    pub const DEFAULT_BLOBS_BY_RANGE_QUOTA: Quota =
        Quota::n_every(NonZeroU64::new(896).unwrap(), 10);
    pub const DEFAULT_BLOBS_BY_ROOT_QUOTA: Quota =
        Quota::n_every(NonZeroU64::new(896).unwrap(), 10);
    // Allow up to `MAX_REQUEST_DATA_COLUMN_SIDECARS` (16384), the maximum number of data
    // column sidecars in a single request from the spec.
    pub const DEFAULT_DATA_COLUMNS_BY_RANGE_QUOTA: Quota =
        Quota::n_every(NonZeroU64::new(16384).unwrap(), 10);
    pub const DEFAULT_DATA_COLUMNS_BY_ROOT_QUOTA: Quota =
        Quota::n_every(NonZeroU64::new(16384).unwrap(), 10);
    pub const DEFAULT_LIGHT_CLIENT_BOOTSTRAP_QUOTA: Quota = Quota::one_every(10);
    pub const DEFAULT_LIGHT_CLIENT_OPTIMISTIC_UPDATE_QUOTA: Quota = Quota::one_every(10);
    pub const DEFAULT_LIGHT_CLIENT_FINALITY_UPDATE_QUOTA: Quota = Quota::one_every(10);
    pub const DEFAULT_LIGHT_CLIENT_UPDATES_BY_RANGE_QUOTA: Quota = Quota::one_every(10);
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        RateLimiterConfig {
            ping_quota: Self::DEFAULT_PING_QUOTA,
            meta_data_quota: Self::DEFAULT_META_DATA_QUOTA,
            status_quota: Self::DEFAULT_STATUS_QUOTA,
            goodbye_quota: Self::DEFAULT_GOODBYE_QUOTA,
            blocks_by_range_quota: Self::DEFAULT_BLOCKS_BY_RANGE_QUOTA,
            blocks_by_root_quota: Self::DEFAULT_BLOCKS_BY_ROOT_QUOTA,
            blobs_by_range_quota: Self::DEFAULT_BLOBS_BY_RANGE_QUOTA,
            blobs_by_root_quota: Self::DEFAULT_BLOBS_BY_ROOT_QUOTA,
            data_columns_by_root_quota: Self::DEFAULT_DATA_COLUMNS_BY_ROOT_QUOTA,
            data_columns_by_range_quota: Self::DEFAULT_DATA_COLUMNS_BY_RANGE_QUOTA,
            light_client_bootstrap_quota: Self::DEFAULT_LIGHT_CLIENT_BOOTSTRAP_QUOTA,
            light_client_optimistic_update_quota:
                Self::DEFAULT_LIGHT_CLIENT_OPTIMISTIC_UPDATE_QUOTA,
            light_client_finality_update_quota: Self::DEFAULT_LIGHT_CLIENT_FINALITY_UPDATE_QUOTA,
            light_client_updates_by_range_quota: Self::DEFAULT_LIGHT_CLIENT_UPDATES_BY_RANGE_QUOTA,
        }
    }
}

impl Debug for RateLimiterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        macro_rules! fmt_q {
            ($quota:expr) => {
                &format_args!(
                    "{}/{}s",
                    $quota.max_tokens,
                    $quota.replenish_all_every.as_secs()
                )
            };
        }

        f.debug_struct("RateLimiterConfig")
            .field("ping", fmt_q!(&self.ping_quota))
            .field("metadata", fmt_q!(&self.meta_data_quota))
            .field("status", fmt_q!(&self.status_quota))
            .field("goodbye", fmt_q!(&self.goodbye_quota))
            .field("blocks_by_range", fmt_q!(&self.blocks_by_range_quota))
            .field("blocks_by_root", fmt_q!(&self.blocks_by_root_quota))
            .field("blobs_by_range", fmt_q!(&self.blobs_by_range_quota))
            .field("blobs_by_root", fmt_q!(&self.blobs_by_root_quota))
            .field(
                "data_columns_by_range",
                fmt_q!(&self.data_columns_by_range_quota),
            )
            .field(
                "data_columns_by_root",
                fmt_q!(&self.data_columns_by_root_quota),
            )
            .finish()
    }
}

/// Parse configurations for the outbound rate limiter. Protocols that are not specified use
/// the default values. Protocol specified more than once use only the first given Quota.
///
/// The expected format is a ';' separated list of [`ProtocolQuota`].
impl FromStr for RateLimiterConfig {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ping_quota = None;
        let mut meta_data_quota = None;
        let mut status_quota = None;
        let mut goodbye_quota = None;
        let mut blocks_by_range_quota = None;
        let mut blocks_by_root_quota = None;
        let mut blobs_by_range_quota = None;
        let mut blobs_by_root_quota = None;
        let mut data_columns_by_root_quota = None;
        let mut data_columns_by_range_quota = None;
        let mut light_client_bootstrap_quota = None;
        let mut light_client_optimistic_update_quota = None;
        let mut light_client_finality_update_quota = None;
        let mut light_client_updates_by_range_quota = None;

        for proto_def in s.split(';') {
            let ProtocolQuota { protocol, quota } = proto_def.parse()?;
            let quota = Some(quota);
            match protocol {
                Protocol::Status => status_quota = status_quota.or(quota),
                Protocol::Goodbye => goodbye_quota = goodbye_quota.or(quota),
                Protocol::BlocksByRange => blocks_by_range_quota = blocks_by_range_quota.or(quota),
                Protocol::BlocksByRoot => blocks_by_root_quota = blocks_by_root_quota.or(quota),
                Protocol::BlobsByRange => blobs_by_range_quota = blobs_by_range_quota.or(quota),
                Protocol::BlobsByRoot => blobs_by_root_quota = blobs_by_root_quota.or(quota),
                Protocol::DataColumnsByRoot => {
                    data_columns_by_root_quota = data_columns_by_root_quota.or(quota)
                }
                Protocol::DataColumnsByRange => {
                    data_columns_by_range_quota = data_columns_by_range_quota.or(quota)
                }
                Protocol::Ping => ping_quota = ping_quota.or(quota),
                Protocol::MetaData => meta_data_quota = meta_data_quota.or(quota),
                Protocol::LightClientBootstrap => {
                    light_client_bootstrap_quota = light_client_bootstrap_quota.or(quota)
                }
                Protocol::LightClientOptimisticUpdate => {
                    light_client_optimistic_update_quota =
                        light_client_optimistic_update_quota.or(quota)
                }
                Protocol::LightClientFinalityUpdate => {
                    light_client_finality_update_quota =
                        light_client_finality_update_quota.or(quota)
                }
                Protocol::LightClientUpdatesByRange => {
                    light_client_updates_by_range_quota =
                        light_client_updates_by_range_quota.or(quota)
                }
            }
        }
        Ok(RateLimiterConfig {
            ping_quota: ping_quota.unwrap_or(Self::DEFAULT_PING_QUOTA),
            meta_data_quota: meta_data_quota.unwrap_or(Self::DEFAULT_META_DATA_QUOTA),
            status_quota: status_quota.unwrap_or(Self::DEFAULT_STATUS_QUOTA),
            goodbye_quota: goodbye_quota.unwrap_or(Self::DEFAULT_GOODBYE_QUOTA),
            blocks_by_range_quota: blocks_by_range_quota
                .unwrap_or(Self::DEFAULT_BLOCKS_BY_RANGE_QUOTA),
            blocks_by_root_quota: blocks_by_root_quota
                .unwrap_or(Self::DEFAULT_BLOCKS_BY_ROOT_QUOTA),
            blobs_by_range_quota: blobs_by_range_quota
                .unwrap_or(Self::DEFAULT_BLOBS_BY_RANGE_QUOTA),
            blobs_by_root_quota: blobs_by_root_quota.unwrap_or(Self::DEFAULT_BLOBS_BY_ROOT_QUOTA),
            data_columns_by_root_quota: data_columns_by_root_quota
                .unwrap_or(Self::DEFAULT_DATA_COLUMNS_BY_ROOT_QUOTA),
            data_columns_by_range_quota: data_columns_by_range_quota
                .unwrap_or(Self::DEFAULT_DATA_COLUMNS_BY_RANGE_QUOTA),
            light_client_bootstrap_quota: light_client_bootstrap_quota
                .unwrap_or(Self::DEFAULT_LIGHT_CLIENT_BOOTSTRAP_QUOTA),
            light_client_optimistic_update_quota: light_client_optimistic_update_quota
                .unwrap_or(Self::DEFAULT_LIGHT_CLIENT_OPTIMISTIC_UPDATE_QUOTA),
            light_client_finality_update_quota: light_client_finality_update_quota
                .unwrap_or(Self::DEFAULT_LIGHT_CLIENT_FINALITY_UPDATE_QUOTA),
            light_client_updates_by_range_quota: light_client_updates_by_range_quota
                .unwrap_or(Self::DEFAULT_LIGHT_CLIENT_UPDATES_BY_RANGE_QUOTA),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_inverse() {
        let quota = ProtocolQuota {
            protocol: Protocol::Goodbye,
            quota: Quota {
                replenish_all_every: Duration::from_secs(10),
                max_tokens: NonZeroU64::new(8).unwrap(),
            },
        };
        assert_eq!(quota.to_string().parse(), Ok(quota))
    }
}
