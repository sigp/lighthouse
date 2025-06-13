use std::sync::{Arc, LazyLock};

use beacon_chain::{
    inclusion_list_verification::GossipInclusionListError,
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconChainTypes, ChainConfig,
};
use bls::{generics::GenericSignature, PublicKeyBytes, SecretKey};
use types::{
    ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, InclusionList, Keypair, MainnetEthSpec,
    SignedInclusionList, SignedRoot, Slot,
};

pub const VALIDATOR_COUNT: usize = 256;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

pub type E = MainnetEthSpec;

/// Returns a beacon chain harness for the eip7805 fork
fn get_harness_eip7805(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));
    spec.bellatrix_fork_epoch = Some(Epoch::new(0));
    spec.capella_fork_epoch = Some(Epoch::new(0));
    spec.deneb_fork_epoch = Some(Epoch::new(0));
    spec.electra_fork_epoch = Some(Epoch::new(0));
    spec.eip7805_fork_epoch = Some(Epoch::new(0));
    let spec = Arc::new(spec);

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec)
        .chain_config(ChainConfig {
            reconstruct_historic_states: true,
            ..ChainConfig::default()
        })
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

pub async fn get_valid_signed_inclusion_list<T: BeaconChainTypes>(
    harness: &BeaconChainHarness<T>,
) -> SignedInclusionList<T::EthSpec> {
    let head = harness.chain.head_snapshot();
    let current_epoch = harness.chain.epoch().expect("should get slot");
    let indices = (0..=256).collect::<Vec<_>>();

    let indices_and_pubkeys: Vec<(usize, PublicKeyBytes)> = harness
        .chain
        .validator_pubkey_bytes_many(&indices)
        .unwrap()
        .into_iter()
        .collect();

    let inclusion_list_duties = harness
        .chain
        .validator_inclusion_list_duties(
            &indices_and_pubkeys,
            current_epoch,
            head.beacon_block_root,
        )
        .unwrap();

    let current_slot = MainnetEthSpec::slots_per_epoch() as usize * 3;

    let duties = inclusion_list_duties.0;

    let mut current_duty_for_slot_opt = None;
    for duty in duties {
        if duty.unwrap().slot == Slot::new(current_slot as u64) {
            current_duty_for_slot_opt = duty;
            break;
        }
    }

    let current_duty_for_slot = current_duty_for_slot_opt.unwrap();

    let inclusion_list = InclusionList {
        slot: current_duty_for_slot.slot,
        validator_index: current_duty_for_slot.validator_index,
        inclusion_list_committee_root: current_duty_for_slot.committee_root,
        transactions: <_>::default(),
    };

    let keypair = &KEYPAIRS[current_duty_for_slot.validator_index as usize];

    let fork = harness.chain.spec.fork_at_epoch(current_epoch);

    let signed_inclusion_list = sign(
        &inclusion_list,
        &keypair.sk,
        &fork,
        harness.chain.genesis_validators_root,
        &harness.chain.spec,
    );

    signed_inclusion_list
}

/// Signs `self`, setting the `committee_position`'th bit of `aggregation_bits` to `true`.
///
/// Returns an `AlreadySigned` error if the `committee_position`'th bit is already `true`.
pub fn sign<E: EthSpec>(
    inclusion_list: &InclusionList<E>,
    secret_key: &SecretKey,
    fork: &Fork,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> SignedInclusionList<E> {
    let domain = spec.get_domain(
        inclusion_list.slot.epoch(E::slots_per_epoch()),
        Domain::InclusionListCommittee,
        fork,
        genesis_validators_root,
    );
    let message_to_sign = inclusion_list.signing_root(domain);

    let signature = secret_key.sign(message_to_sign);

    SignedInclusionList {
        message: inclusion_list.clone(),
        signature,
    }
}

struct InclusionListGossipTester {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,

    /*
     * Valid inclusion list
     */
    inclusion_list: SignedInclusionList<E>,
}

impl InclusionListGossipTester {
    pub async fn new() -> Self {
        let harness = get_harness_eip7805(VALIDATOR_COUNT);

        // Extend the chain out a few epochs so we have some chain depth to play with.
        harness
            .extend_chain(
                MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        // Advance into a slot where there have not been blocks or attestations produced.
        harness.advance_slot();

        let inclusion_list = get_valid_signed_inclusion_list(&harness).await;

        Self {
            harness,
            inclusion_list,
        }
    }

    pub fn import_valid_inclusion_list(self) -> Self {
        self.harness
            .chain
            .verify_inclusion_list_for_gossip(&self.inclusion_list)
            .unwrap();

        self.harness
            .chain
            .on_verified_inclusion_list(self.inclusion_list.clone());
        self
    }

    pub fn inspect_inclusion_list_err<G, I>(
        self,
        desc: &str,
        get_inclusion_list: G,
        inspect_err: I,
    ) -> Self
    where
        G: Fn(&Self, &mut SignedInclusionList<E>),
        I: Fn(&Self, GossipInclusionListError),
    {
        let mut il = self.inclusion_list.clone();
        get_inclusion_list(&self, &mut il);

        /*
         * Individual verification
         */
        let err = self
            .harness
            .chain
            .verify_inclusion_list_for_gossip(&il)
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{} should error during verify_inclusion_list_for_gossip",
                    desc
                )
            });

        inspect_err(&self, err);
        self
    }
}

/// Tests verification of `SignedInclusionList` from the gossip network.
#[tokio::test]
async fn inclusion_list_verification() {
    InclusionListGossipTester::new()
        .await
        .inspect_inclusion_list_err(
            "inclusion list from past slot",
            |_, il| {
                il.message.slot = Slot::new(0);
            },
            |_, error| {
                assert!(matches!(
                    error,
                    GossipInclusionListError::InvalidSlot { .. }
                ))
            },
        )
        .inspect_inclusion_list_err(
            "inclusion list with invalid committee root",
            |_, il| {
                il.message.inclusion_list_committee_root = Hash256::default();
            },
            |_, error| {
                assert!(matches!(
                    error,
                    GossipInclusionListError::InvalidCommitteeRoot
                ))
            },
        )
        .inspect_inclusion_list_err(
            "inclusion list with invalid signature",
            |_, il| {
                il.signature = GenericSignature::empty();
            },
            |_, error| assert!(matches!(error, GossipInclusionListError::InvalidSignature)),
        )
        .inspect_inclusion_list_err(
            "inclusion list with a validator index that doesn't belong in the committee",
            |_, il| {
                il.message.validator_index = 9999;
            },
            |_, error| {
                assert!(matches!(
                    error,
                    GossipInclusionListError::ValidatorNotInCommittee
                ))
            },
        )
        .inspect_inclusion_list_err(
            "inclusion list with too many transactions",
            |_, il| {
                il.message.transactions = vec![vec![0u8; 5].into(); 8193].into();
            },
            |_, error| {
                assert!(matches!(
                    error,
                    GossipInclusionListError::TooManyTransactions
                ))
            },
        )
        // verify and import the valid inclusion list
        .import_valid_inclusion_list()
        .inspect_inclusion_list_err(
            "inclusion list has already been seen over gossip",
            |_, _| {},
            |_, error| {
                assert!(matches!(
                    error,
                    GossipInclusionListError::PriorInclusionListKnown
                ))
            },
        );
}
