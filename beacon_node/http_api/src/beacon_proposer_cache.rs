use crate::metrics;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::ProposerData;
use fork_choice::ProtoBlock;
use slot_clock::SlotClock;
use state_processing::per_slot_processing;
use types::{Epoch, EthSpec, Hash256, PublicKeyBytes};

/// This sets a maximum bound on the number of epochs to skip whilst instantiating the cache for
/// the first time.
const EPOCHS_TO_SKIP: u64 = 2;

/// Caches the beacon block proposers for a given `epoch` and `epoch_boundary_root`.
///
/// This cache is only able to contain a single set of proposers and is only
/// intended to cache the proposers for the current epoch according to the head
/// of the chain. A change in epoch or re-org to a different chain may cause a
/// cache miss and rebuild.
pub struct BeaconProposerCache {
    epoch: Epoch,
    epoch_boundary_root: Hash256,
    proposers: Vec<ProposerData>,
}

impl BeaconProposerCache {
    /// Create a new cache for the current epoch of the `chain`.
    pub fn new<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Result<Self, BeaconChainError> {
        let (head_root, head_block) = Self::current_head_block(chain)?;

        // If the head epoch is more than `EPOCHS_TO_SKIP` in the future, just build the cache at
        // the epoch of the head. This prevents doing a massive amount of skip slots when starting
        // a new database from genesis.
        let epoch = {
            let epoch_now = chain
                .epoch()
                .unwrap_or_else(|_| chain.spec.genesis_slot.epoch(T::EthSpec::slots_per_epoch()));
            let head_epoch = head_block.slot.epoch(T::EthSpec::slots_per_epoch());
            if epoch_now > head_epoch + EPOCHS_TO_SKIP {
                head_epoch
            } else {
                epoch_now
            }
        };

        Self::for_head_block(chain, epoch, head_root, head_block)
    }

    /// Create a new cache that contains the shuffling for `current_epoch`,
    /// assuming that `head_root` and `head_block` represents the most recent
    /// canonical block.
    fn for_head_block<T: BeaconChainTypes>(
        chain: &BeaconChain<T>,
        current_epoch: Epoch,
        head_root: Hash256,
        head_block: ProtoBlock,
    ) -> Result<Self, BeaconChainError> {
        let _timer = metrics::start_timer(&metrics::HTTP_API_BEACON_PROPOSER_CACHE_TIMES);

        let mut head_state = chain
            .get_state(&head_block.state_root, Some(head_block.slot))?
            .ok_or_else(|| BeaconChainError::MissingBeaconState(head_block.state_root))?;

        // We *must* skip forward to the current epoch to obtain valid proposer
        // duties. We cannot skip to the previous epoch, like we do with
        // attester duties.
        while head_state.current_epoch() < current_epoch {
            // Skip slots until the current epoch, providing `Hash256::zero()` as the state root
            // since we don't require it to be valid to identify producers.
            per_slot_processing(&mut head_state, Some(Hash256::zero()), &chain.spec)?;
        }

        let proposers = current_epoch
            .slot_iter(T::EthSpec::slots_per_epoch())
            .map(|slot| {
                head_state
                    .get_beacon_proposer_index(slot, &chain.spec)
                    .map_err(BeaconChainError::from)
                    .and_then(|i| {
                        let pubkey = chain
                            .validator_pubkey(i)?
                            .ok_or_else(|| BeaconChainError::ValidatorPubkeyCacheIncomplete(i))?;

                        Ok(ProposerData {
                            pubkey: PublicKeyBytes::from(pubkey),
                            slot,
                        })
                    })
            })
            .collect::<Result<_, _>>()?;

        let epoch_boundary_slot = head_state
            .current_epoch()
            .start_slot(T::EthSpec::slots_per_epoch());
        let epoch_boundary_root = if head_state.slot >= epoch_boundary_slot {
            head_root
        } else {
            *head_state.get_block_root(epoch_boundary_slot)?
        };

        Ok(Self {
            epoch: current_epoch,
            epoch_boundary_root,
            proposers,
        })
    }

    /// Return the proposers for the given `Epoch`.
    ///
    /// The cache may be rebuilt if:
    ///
    /// - The epoch has changed since the last cache build.
    /// - There has been a re-org that crosses an epoch boundary.
    pub fn get_proposers<T: BeaconChainTypes>(
        &mut self,
        chain: &BeaconChain<T>,
        epoch: Epoch,
    ) -> Result<Vec<ProposerData>, warp::Rejection> {
        let is_prior_to_genesis = chain.slot_clock.is_prior_to_genesis().ok_or_else(|| {
            warp_utils::reject::custom_server_error("unable to read slot clock".to_string())
        })?;
        let current_epoch = if is_prior_to_genesis {
            chain.spec.genesis_slot.epoch(T::EthSpec::slots_per_epoch())
        } else {
            chain
                .epoch()
                .map_err(warp_utils::reject::beacon_chain_error)?
        };

        // Disallow requests that are outside the current epoch. This ensures the cache doesn't get
        // washed-out with old values.
        if current_epoch != epoch {
            return Err(warp_utils::reject::custom_bad_request(format!(
                "requested epoch is {} but only current epoch {} is allowed",
                epoch, current_epoch
            )));
        }

        let (head_root, head_block) =
            Self::current_head_block(chain).map_err(warp_utils::reject::beacon_chain_error)?;
        let epoch_boundary_root = head_block.target_root;

        // Rebuild the cache if this call causes a cache-miss.
        if self.epoch != current_epoch || self.epoch_boundary_root != epoch_boundary_root {
            metrics::inc_counter(&metrics::HTTP_API_BEACON_PROPOSER_CACHE_MISSES_TOTAL);

            *self = Self::for_head_block(chain, current_epoch, head_root, head_block)
                .map_err(warp_utils::reject::beacon_chain_error)?;
        } else {
            metrics::inc_counter(&metrics::HTTP_API_BEACON_PROPOSER_CACHE_HITS_TOTAL);
        }

        Ok(self.proposers.clone())
    }

    /// Use fork choice to obtain some information about the head block of `chain`.
    fn current_head_block<T: BeaconChainTypes>(
        chain: &BeaconChain<T>,
    ) -> Result<(Hash256, ProtoBlock), BeaconChainError> {
        let head_root = chain.head_beacon_block_root()?;

        chain
            .fork_choice
            .read()
            .get_block(&head_root)
            .ok_or_else(|| BeaconChainError::MissingBeaconBlock(head_root))
            .map(|head_block| (head_root, head_block))
    }
}
