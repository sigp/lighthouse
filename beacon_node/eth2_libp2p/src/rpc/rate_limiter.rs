use crate::rpc::{InboundRequest, Protocol};
use fnv::FnvHashMap;
use libp2p::PeerId;
use std::convert::TryInto;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::time::Interval;
use types::EthSpec;

/// Nanoseconds since a given time.
// Maintained as u64 to reduce footprint
// NOTE: this also implies that the rate limiter will manage checking if a batch is allowed for at
//       most <init time> + u64::MAX nanosecs, ~500 years. So it is realistic to assume this is fine.
type Nanosecs = u64;

/// User-friendly rate limiting parameters of the GCRA.
///
/// A quota of `max_tokens` tokens every `replenish_all_every` units of time means that:
/// 1. One token is replenished every `replenish_all_every`/`max_tokens` units of time.
/// 2. Instantaneous bursts (batches) of up to `max_tokens` tokens are allowed.
///
/// The above implies that if `max_tokens` is greater than 1, the perceived rate may be higher (but
/// bounded) than the defined rate when instantaneous bursts occur. For instance, for a rate of
/// 4T/2s a first burst of 4T is allowed with subsequent requests of 1T every 0.5s forever,
/// producing a perceived rate over the window of the first 2s of 8T. However, subsequent sliding
/// windows of 2s keep the limit.
///
/// In this scenario using the same rate as above, the sender is always maxing out their tokens,
/// except at seconds 1.5, 3, 3.5 and 4
///
/// ```ignore
///            x
///      used  x
///    tokens  x           x           x
///      at a  x  x  x     x  x        x
///     given  +--+--+--o--+--+--o--o--o--> seconds
///      time  |  |  |  |  |  |  |  |  |
///            0     1     2     3     4
///
///            4  1  1  1  2  1  1  2  3 <= available tokens when the batch is received
/// ```
///
/// For a sender to request a batch of `n`T, they would need to wait at least
/// n*`replenish_all_every`/`max_tokens` units of time since their last request.
///
/// To produce hard limits, set `max_tokens` to 1.
pub struct Quota {
    /// How often are `max_tokens` fully replenished.
    replenish_all_every: Duration,
    /// Token limit. This translates on how large can an instantaneous batch of
    /// tokens be.
    max_tokens: u64,
}

/// Manages rate limiting of requests per peer, with differentiated rates per protocol.
pub struct RPCRateLimiter {
    /// Interval to prune peers for which their timer ran out.
    prune_interval: Interval,
    /// Creation time of the rate limiter.
    init_time: Instant,
    /// Goodbye rate limiter.
    goodbye_rl: Limiter<PeerId>,
    /// Ping rate limiter.
    ping_rl: Limiter<PeerId>,
    /// MetaData rate limiter.
    metadata_rl: Limiter<PeerId>,
    /// Status rate limiter.
    status_rl: Limiter<PeerId>,
    /// BlocksByRange rate limiter.
    bbrange_rl: Limiter<PeerId>,
    /// BlocksByRoot rate limiter.
    bbroots_rl: Limiter<PeerId>,
}

/// Error type for non conformant requests
pub enum RateLimitedErr {
    /// Required tokens for this request exceed the maximum
    TooLarge,
    /// Request does not fit in the quota. Gives the earliest time the request could be accepted.
    TooSoon(Duration),
}

/// User-friendly builder of a `RPCRateLimiter`
#[derive(Default)]
pub struct RPCRateLimiterBuilder {
    /// Quota for the Goodbye protocol.
    goodbye_quota: Option<Quota>,
    /// Quota for the Ping protocol.
    ping_quota: Option<Quota>,
    /// Quota for the MetaData protocol.
    metadata_quota: Option<Quota>,
    /// Quota for the Status protocol.
    status_quota: Option<Quota>,
    /// Quota for the BlocksByRange protocol.
    bbrange_quota: Option<Quota>,
    /// Quota for the BlocksByRoot protocol.
    bbroots_quota: Option<Quota>,
}

impl RPCRateLimiterBuilder {
    /// Get an empty `RPCRateLimiterBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set a quota for a protocol.
    fn set_quota(mut self, protocol: Protocol, quota: Quota) -> Self {
        let q = Some(quota);
        match protocol {
            Protocol::Ping => self.ping_quota = q,
            Protocol::Status => self.status_quota = q,
            Protocol::MetaData => self.metadata_quota = q,
            Protocol::Goodbye => self.goodbye_quota = q,
            Protocol::BlocksByRange => self.bbrange_quota = q,
            Protocol::BlocksByRoot => self.bbroots_quota = q,
        }
        self
    }

    /// Allow one token every `time_period` to be used for this `protocol`.
    /// This produces a hard limit.
    pub fn one_every(self, protocol: Protocol, time_period: Duration) -> Self {
        self.set_quota(
            protocol,
            Quota {
                replenish_all_every: time_period,
                max_tokens: 1,
            },
        )
    }

    /// Allow `n` tokens to be use used every `time_period` for this `protocol`.
    pub fn n_every(self, protocol: Protocol, n: u64, time_period: Duration) -> Self {
        self.set_quota(
            protocol,
            Quota {
                max_tokens: n,
                replenish_all_every: time_period,
            },
        )
    }

    pub fn build(self) -> Result<RPCRateLimiter, &'static str> {
        // get our quotas
        let ping_quota = self.ping_quota.ok_or("Ping quota not specified")?;
        let metadata_quota = self.metadata_quota.ok_or("MetaData quota not specified")?;
        let status_quota = self.status_quota.ok_or("Status quota not specified")?;
        let goodbye_quota = self.goodbye_quota.ok_or("Goodbye quota not specified")?;
        let bbroots_quota = self
            .bbroots_quota
            .ok_or("BlocksByRoot quota not specified")?;
        let bbrange_quota = self
            .bbrange_quota
            .ok_or("BlocksByRange quota not specified")?;

        // create the rate limiters
        let ping_rl = Limiter::from_quota(ping_quota)?;
        let metadata_rl = Limiter::from_quota(metadata_quota)?;
        let status_rl = Limiter::from_quota(status_quota)?;
        let goodbye_rl = Limiter::from_quota(goodbye_quota)?;
        let bbroots_rl = Limiter::from_quota(bbroots_quota)?;
        let bbrange_rl = Limiter::from_quota(bbrange_quota)?;

        // check for peers to prune every 30 seconds, starting in 30 seconds
        let prune_every = tokio::time::Duration::from_secs(30);
        let prune_start = tokio::time::Instant::now() + prune_every;
        let prune_interval = tokio::time::interval_at(prune_start, prune_every);
        Ok(RPCRateLimiter {
            prune_interval,
            ping_rl,
            metadata_rl,
            status_rl,
            goodbye_rl,
            bbroots_rl,
            bbrange_rl,
            init_time: Instant::now(),
        })
    }
}

impl RPCRateLimiter {
    pub fn allows<T: EthSpec>(
        &mut self,
        peer_id: &PeerId,
        request: &InboundRequest<T>,
    ) -> Result<(), RateLimitedErr> {
        let time_since_start = self.init_time.elapsed();
        let mut tokens = request.expected_responses().max(1);

        // Increase the rate limit for blocks by range requests with large step counts.
        // We count to tokens as a quadratic increase with step size.
        // Using (step_size/5)^2 + 1 as penalty factor allows step sizes of 1-4 to have no penalty
        // but step sizes higher than this add a quadratic penalty.
        // Penalty's go:
        // Step size | Penalty Factor
        //     1     |   1
        //     2     |   1
        //     3     |   1
        //     4     |   1
        //     5     |   2
        //     6     |   2
        //     7     |   2
        //     8     |   3
        //     9     |   4
        //     10    |   5

        if let InboundRequest::BlocksByRange(bbr_req) = request {
            let penalty_factor = (bbr_req.step as f64 / 5.0).powi(2) as u64 + 1;
            tokens *= penalty_factor;
        }

        let check =
            |limiter: &mut Limiter<PeerId>| limiter.allows(time_since_start, peer_id, tokens);
        let limiter = match request.protocol() {
            Protocol::Ping => &mut self.ping_rl,
            Protocol::Status => &mut self.status_rl,
            Protocol::MetaData => &mut self.metadata_rl,
            Protocol::Goodbye => &mut self.goodbye_rl,
            Protocol::BlocksByRange => &mut self.bbrange_rl,
            Protocol::BlocksByRoot => &mut self.bbroots_rl,
        };
        check(limiter)
    }

    pub fn prune(&mut self) {
        let time_since_start = self.init_time.elapsed();
        self.ping_rl.prune(time_since_start);
        self.status_rl.prune(time_since_start);
        self.metadata_rl.prune(time_since_start);
        self.goodbye_rl.prune(time_since_start);
        self.bbrange_rl.prune(time_since_start);
        self.bbroots_rl.prune(time_since_start);
    }
}

impl Future for RPCRateLimiter {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        while self.prune_interval.poll_tick(cx).is_ready() {
            self.prune();
        }

        Poll::Pending
    }
}

/// Per key rate limiter using the token bucket / leaky bucket as a meter rate limiting algorithm,
/// with the GCRA implementation.
pub struct Limiter<Key: Hash + Eq + Clone> {
    /// After how long is the bucket considered full via replenishing 1T every `t`.
    tau: Nanosecs,
    /// How often is 1T replenished.
    t: Nanosecs,
    /// Time when the bucket will be full for each peer. TAT (theoretical arrival time) from GCRA.
    tat_per_key: FnvHashMap<Key, Nanosecs>,
}

impl<Key: Hash + Eq + Clone> Limiter<Key> {
    pub fn from_quota(quota: Quota) -> Result<Self, &'static str> {
        if quota.max_tokens == 0 {
            return Err("Max number of tokens should be positive");
        }
        let tau = quota.replenish_all_every.as_nanos();
        if tau == 0 {
            return Err("Replenish time must be positive");
        }
        let t = (tau / quota.max_tokens as u128)
            .try_into()
            .map_err(|_| "total replenish time is too long")?;
        let tau = tau
            .try_into()
            .map_err(|_| "total replenish time is too long")?;
        Ok(Limiter {
            tau,
            t,
            tat_per_key: FnvHashMap::default(),
        })
    }

    pub fn allows(
        &mut self,
        time_since_start: Duration,
        key: &Key,
        tokens: u64,
    ) -> Result<(), RateLimitedErr> {
        let time_since_start = time_since_start.as_nanos() as u64;
        let tau = self.tau;
        let t = self.t;
        // how long does it take to replenish these tokens
        let additional_time = t * tokens;
        if additional_time > tau {
            // the time required to process this amount of tokens is longer than the time that
            // makes the bucket full. So, this batch can _never_ be processed
            return Err(RateLimitedErr::TooLarge);
        }
        // If the key is new, we consider their bucket full (which means, their request will be
        // allowed)
        let tat = self
            .tat_per_key
            .entry(key.clone())
            .or_insert(time_since_start);
        // check how soon could the request be made
        let earliest_time = (*tat + additional_time).saturating_sub(tau);
        // earliest_time is in the future
        if time_since_start < earliest_time {
            Err(RateLimitedErr::TooSoon(Duration::from_nanos(
                /* time they need to wait, i.e. how soon were they */
                earliest_time - time_since_start,
            )))
        } else {
            // calculate the new TAT
            *tat = time_since_start.max(*tat) + additional_time;
            Ok(())
        }
    }

    /// Removes keys for which their bucket is full by `time_limit`
    pub fn prune(&mut self, time_limit: Duration) {
        let lim = &mut (time_limit.as_nanos() as u64);
        // remove those for which tat < lim
        self.tat_per_key.retain(|_k, tat| tat >= lim)
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::rate_limiter::{Limiter, Quota};
    use std::time::Duration;

    #[test]
    fn it_works_a() {
        let mut limiter = Limiter::from_quota(Quota {
            replenish_all_every: Duration::from_secs(2),
            max_tokens: 4,
        })
        .unwrap();
        let key = 10;
        //        x
        //  used  x
        // tokens x           x
        //        x  x  x     x
        //        +--+--+--+--+----> seconds
        //        |  |  |  |  |
        //        0     1     2

        assert!(limiter
            .allows(Duration::from_secs_f32(0.0), &key, 4)
            .is_ok());
        limiter.prune(Duration::from_secs_f32(0.1));
        assert!(limiter
            .allows(Duration::from_secs_f32(0.1), &key, 1)
            .is_err());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.5), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(1.0), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(1.4), &key, 1)
            .is_err());
        assert!(limiter
            .allows(Duration::from_secs_f32(2.0), &key, 2)
            .is_ok());
    }

    #[test]
    fn it_works_b() {
        let mut limiter = Limiter::from_quota(Quota {
            replenish_all_every: Duration::from_secs(2),
            max_tokens: 4,
        })
        .unwrap();
        let key = 10;
        // if we limit to 4T per 2s, check that 4 requests worth 1 token can be sent before the
        // first half second, when one token will be available again. Check also that before
        // regaining a token, another request is rejected

        assert!(limiter
            .allows(Duration::from_secs_f32(0.0), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.1), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.2), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.3), &key, 1)
            .is_ok());
        assert!(limiter
            .allows(Duration::from_secs_f32(0.4), &key, 1)
            .is_err());
    }
}
