use std::{
    fmt::{Debug, Display},
    str::FromStr,
    time::Duration,
};

use super::{methods, rate_limiter::Quota, Protocol};

use serde_derive::{Deserialize, Serialize};

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

/// Configurations for the rate limiter applied to outbound requests (made by the node itself).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundRateLimiterConfig {
    pub(super) ping_quota: Quota,
    pub(super) meta_data_quota: Quota,
    pub(super) status_quota: Quota,
    pub(super) goodbye_quota: Quota,
    pub(super) blocks_by_range_quota: Quota,
    pub(super) blocks_by_root_quota: Quota,
}

impl OutboundRateLimiterConfig {
    pub const DEFAULT_PING_QUOTA: Quota = Quota::n_every(2, 10);
    pub const DEFAULT_META_DATA_QUOTA: Quota = Quota::n_every(2, 5);
    pub const DEFAULT_STATUS_QUOTA: Quota = Quota::n_every(5, 15);
    pub const DEFAULT_GOODBYE_QUOTA: Quota = Quota::one_every(10);
    pub const DEFAULT_BLOCKS_BY_RANGE_QUOTA: Quota =
        Quota::n_every(methods::MAX_REQUEST_BLOCKS, 10);
    pub const DEFAULT_BLOCKS_BY_ROOT_QUOTA: Quota = Quota::n_every(128, 10);
}

impl Default for OutboundRateLimiterConfig {
    fn default() -> Self {
        OutboundRateLimiterConfig {
            ping_quota: Self::DEFAULT_PING_QUOTA,
            meta_data_quota: Self::DEFAULT_META_DATA_QUOTA,
            status_quota: Self::DEFAULT_STATUS_QUOTA,
            goodbye_quota: Self::DEFAULT_GOODBYE_QUOTA,
            blocks_by_range_quota: Self::DEFAULT_BLOCKS_BY_RANGE_QUOTA,
            blocks_by_root_quota: Self::DEFAULT_BLOCKS_BY_ROOT_QUOTA,
        }
    }
}

impl Debug for OutboundRateLimiterConfig {
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

        f.debug_struct("OutboundRateLimiterConfig")
            .field("ping", fmt_q!(&self.ping_quota))
            .field("metadata", fmt_q!(&self.meta_data_quota))
            .field("status", fmt_q!(&self.status_quota))
            .field("goodbye", fmt_q!(&self.goodbye_quota))
            .field("blocks_by_range", fmt_q!(&self.blocks_by_range_quota))
            .field("blocks_by_root", fmt_q!(&self.blocks_by_root_quota))
            .finish()
    }
}

/// Parse configurations for the outbound rate limiter. Protocols that are not specified use
/// the default values. Protocol specified more than once use only the first given Quota.
///
/// The expected format is a ';' separated list of [`ProtocolQuota`].
impl FromStr for OutboundRateLimiterConfig {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ping_quota = None;
        let mut meta_data_quota = None;
        let mut status_quota = None;
        let mut goodbye_quota = None;
        let mut blocks_by_range_quota = None;
        let mut blocks_by_root_quota = None;
        for proto_def in s.split(';') {
            let ProtocolQuota { protocol, quota } = proto_def.parse()?;
            let quota = Some(quota);
            match protocol {
                Protocol::Status => status_quota = status_quota.or(quota),
                Protocol::Goodbye => goodbye_quota = goodbye_quota.or(quota),
                Protocol::BlocksByRange => blocks_by_range_quota = blocks_by_range_quota.or(quota),
                Protocol::BlocksByRoot => blocks_by_root_quota = blocks_by_root_quota.or(quota),
                Protocol::Ping => ping_quota = ping_quota.or(quota),
                Protocol::MetaData => meta_data_quota = meta_data_quota.or(quota),
                Protocol::LightClientBootstrap => return Err("Lighthouse does not send LightClientBootstrap requests. Quota should not be set."),
            }
        }
        Ok(OutboundRateLimiterConfig {
            ping_quota: ping_quota.unwrap_or(Self::DEFAULT_PING_QUOTA),
            meta_data_quota: meta_data_quota.unwrap_or(Self::DEFAULT_META_DATA_QUOTA),
            status_quota: status_quota.unwrap_or(Self::DEFAULT_STATUS_QUOTA),
            goodbye_quota: goodbye_quota.unwrap_or(Self::DEFAULT_GOODBYE_QUOTA),
            blocks_by_range_quota: blocks_by_range_quota
                .unwrap_or(Self::DEFAULT_BLOCKS_BY_RANGE_QUOTA),
            blocks_by_root_quota: blocks_by_root_quota
                .unwrap_or(Self::DEFAULT_BLOCKS_BY_ROOT_QUOTA),
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
                max_tokens: 8,
            },
        };
        assert_eq!(quota.to_string().parse(), Ok(quota))
    }
}
