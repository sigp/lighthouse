use crate::{RequestLimits, SourceError, UpdateRange};
use std::future::Future;
use types::{
    EthSpec, ForkName, Hash256, LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate,
};

/// An untrusted object with the fork context used to decode it.
///
/// The format can be newer than an embedded historical header's fork. Neither the metadata nor
/// successful decoding authenticates the object's contents; callers must use the core verifier.
#[derive(Debug, Clone, PartialEq)]
pub struct LightClientData<T> {
    pub data_fork: ForkName,
    pub data: T,
}

/// A decoded response with transport accounting, not proof of validity or progress.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceResponse<T> {
    pub data: T,
    /// Body bytes delivered to the decoder, after any content decompression, including envelopes.
    /// Sources must measure these locally, not trust a provider's Content-Length. An in-memory
    /// source may report zero. The caller accounts for failures via [`SourceError::bytes_received`].
    pub bytes_received: u64,
}

pub type SourceResult<T> = Result<SourceResponse<T>, SourceError>;

/// Sequential, cancellable reads from a light-client provider, independent of `BeaconChain`.
///
/// Implementations must enforce `limits` while receiving either success or error bodies and
/// report byte usage even on failure. Dropping a future must stop scheduling I/O and must not
/// mutate trusted consumer state. No method validates, upgrades or advances a light-client store.
/// Sources may be stateful; the mutable borrow permits scripted fixtures without interior locks.
/// Returned futures are `Send` so callers can use Lighthouse's existing task executor.
pub trait LightClientDataSource<E: EthSpec>: Send {
    fn get_bootstrap(
        &mut self,
        block_root: Hash256,
        limits: RequestLimits,
    ) -> impl Future<Output = SourceResult<LightClientData<LightClientBootstrap<E>>>> + Send;

    /// Request updates for the given attested-period range, in ascending period order.
    /// An empty or short response does not prove coverage. Consumers must check response count,
    /// periods and committee continuity; a successful source call is not a complete catch-up.
    fn get_updates(
        &mut self,
        range: UpdateRange,
        limits: RequestLimits,
    ) -> impl Future<Output = SourceResult<Vec<LightClientData<LightClientUpdate<E>>>>> + Send;

    fn get_finality_update(
        &mut self,
        limits: RequestLimits,
    ) -> impl Future<Output = SourceResult<LightClientData<LightClientFinalityUpdate<E>>>> + Send;
}
