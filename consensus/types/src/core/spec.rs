//! Compile-time `Spec` selection, and the preset constants of each spec.
//!
//! The typenum types of `EthSpec` are built from these constants.

use crate::{GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};

/// All spec constants and their mainnet (default) values.
///
/// Single source of truth for the complete set of spec constants.
/// Each constant is listed exactly once with its mainnet value. Specs that
/// differ from mainnet provide overrides in `define_spec!`.
macro_rules! all_spec_consts {
    ($callback:ident, $($prefix:tt)*) => {
        $callback!(
            $($prefix)*
            GENESIS_EPOCH = 0,
            JUSTIFICATION_BITS_LENGTH = 4,
            SUBNET_BITFIELD_LENGTH = 64,
            MAX_VALIDATORS_PER_COMMITTEE = 2048,
            MAX_COMMITTEES_PER_SLOT = 64,
            MAX_VALIDATORS_PER_SLOT = 131072,
            SLOTS_PER_EPOCH = 32,
            EPOCHS_PER_ETH1_VOTING_PERIOD = 64,
            SLOTS_PER_HISTORICAL_ROOT = 8192,
            EPOCHS_PER_HISTORICAL_VECTOR = 65536,
            EPOCHS_PER_SLASHINGS_VECTOR = 8192,
            HISTORICAL_ROOTS_LIMIT = 16777216,
            VALIDATOR_REGISTRY_LIMIT = 1099511627776,
            BUILDER_PENDING_PAYMENTS_LIMIT = 64,
            MAX_PROPOSER_SLASHINGS = 16,
            MAX_ATTESTER_SLASHINGS = 2,
            MAX_ATTESTATIONS = 128,
            MAX_DEPOSITS = 16,
            MAX_VOLUNTARY_EXITS = 16,
            SYNC_COMMITTEE_SIZE = 512,
            SYNC_COMMITTEE_SUBNET_COUNT = 4,
            MAX_BYTES_PER_TRANSACTION = 1073741824,
            MAX_TRANSACTIONS_PER_PAYLOAD = 1048576,
            BYTES_PER_LOGS_BLOOM = 256,
            GAS_LIMIT_DENOMINATOR = 1024,
            MIN_GAS_LIMIT = 5000,
            MAX_EXTRA_DATA_BYTES = 32,
            MAX_BLS_TO_EXECUTION_CHANGES = 16,
            MAX_WITHDRAWALS_PER_PAYLOAD = 16,
            MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096,
            BYTES_PER_FIELD_ELEMENT = 32,
            FIELD_ELEMENTS_PER_BLOB = 4096,
            FIELD_ELEMENTS_PER_CELL = 64,
            FIELD_ELEMENTS_PER_EXT_BLOB = 8192,
            BYTES_PER_BLOB = 131072,
            BYTES_PER_CELL = 2048,
            MAX_CELLS_PER_BLOCK = 33554432,
            KZG_COMMITMENT_INCLUSION_PROOF_DEPTH = 17,
            KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH = 4,
            CELLS_PER_EXT_BLOB = 128,
            NUMBER_OF_COLUMNS = 128,
            PROPOSER_LOOKAHEAD_SLOTS = 64,
            SYNC_SUBCOMMITTEE_SIZE = 128,
            MAX_PENDING_ATTESTATIONS = 4096,
            SLOTS_PER_ETH1_VOTING_PERIOD = 2048,
            PENDING_DEPOSITS_LIMIT = 134217728,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT = 134217728,
            PENDING_CONSOLIDATIONS_LIMIT = 262144,
            MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD = 2,
            MAX_DEPOSIT_REQUESTS_PER_PAYLOAD = 8192,
            MAX_ATTESTER_SLASHINGS_ELECTRA = 1,
            MAX_ATTESTATIONS_ELECTRA = 8,
            MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD = 16,
            MAX_PENDING_DEPOSITS_PER_EPOCH = 16,
            PTC_SIZE = 512,
            PTC_WINDOW_LENGTH = 96,
            MAX_PAYLOAD_ATTESTATIONS = 4,
            MAX_BUILDERS_PER_WITHDRAWALS_SWEEP = 16384,
            MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD = 64,
            MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD = 16,
            INCLUSION_LIST_COMMITTEE_SIZE = 16,
        );
    };
}

/// For each constant, resolve its value by calling the `__value_for!`
/// macro (defined by `define_spec!`) which checks for an override
/// before falling back to the mainnet default.
macro_rules! __define_impl {
    ($name:ident, $($const_name:ident = $default:expr),* $(,)?) => {
        impl $name {
            $(pub const $const_name: usize = __value_for!($const_name, $default);)*
        }
    };
}

/// Define all spec constants on a concrete struct.
///
/// Constants not listed in the overrides block inherit mainnet default values
/// from `all_spec_consts!`. For mainnet itself, the overrides block is empty.
macro_rules! define_spec {
    ($name:ident, { $($override_name:ident = $override_val:expr),* $(,)? }) => {
        macro_rules! __value_for {
            // One arm per override: literal ident match takes priority.
            $(($override_name, $_d:expr) => { $override_val };)*
            // Fallback: use the mainnet default from all_spec_consts.
            ($other:ident, $default:expr) => { $default };
        }

        all_spec_consts!(__define_impl, $name,);

        // Fails to compile if an override names an unknown constant.
        const _: () = { $(let _ = $name::$override_name;)* };
    };
}

// Spec definitions including overrides when const values differ from mainnet.
define_spec!(MainnetEthSpec, {});

define_spec!(MinimalEthSpec, {
    MAX_COMMITTEES_PER_SLOT = 4,
    MAX_VALIDATORS_PER_SLOT = 8192,
    SLOTS_PER_EPOCH = 8,
    EPOCHS_PER_ETH1_VOTING_PERIOD = 4,
    SLOTS_PER_HISTORICAL_ROOT = 64,
    EPOCHS_PER_HISTORICAL_VECTOR = 64,
    EPOCHS_PER_SLASHINGS_VECTOR = 64,
    SYNC_COMMITTEE_SIZE = 32,
    SYNC_SUBCOMMITTEE_SIZE = 8,
    MAX_PENDING_ATTESTATIONS = 1024,
    SLOTS_PER_ETH1_VOTING_PERIOD = 32,
    MAX_WITHDRAWALS_PER_PAYLOAD = 4,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT = 64,
    PENDING_CONSOLIDATIONS_LIMIT = 64,
    PROPOSER_LOOKAHEAD_SLOTS = 16,
    BUILDER_PENDING_PAYMENTS_LIMIT = 16,
    PTC_SIZE = 16,
    PTC_WINDOW_LENGTH = 24,
    MAX_BUILDERS_PER_WITHDRAWALS_SWEEP = 16,
});

define_spec!(GnosisEthSpec, {
    SLOTS_PER_EPOCH = 16,
    BUILDER_PENDING_PAYMENTS_LIMIT = 32,
    MAX_WITHDRAWALS_PER_PAYLOAD = 8,
    MAX_PENDING_ATTESTATIONS = 2048,
    SLOTS_PER_ETH1_VOTING_PERIOD = 1024,
    PROPOSER_LOOKAHEAD_SLOTS = 32,
    MAX_PAYLOAD_ATTESTATIONS = 2,
    PTC_WINDOW_LENGTH = 48,
});

#[cfg(all(feature = "spec-minimal", feature = "spec-gnosis"))]
compile_error!(
    "`spec-minimal` and `spec-gnosis` select different presets and are mutually exclusive. \
     Enable at most one."
);

/// The spec selected at compile time.
///
/// This allows tests to compile under a single preset.
#[cfg(not(any(feature = "spec-minimal", feature = "spec-gnosis")))]
pub type Spec = MainnetEthSpec;

#[cfg(feature = "spec-minimal")]
pub type Spec = MinimalEthSpec;

#[cfg(all(feature = "spec-gnosis", not(feature = "spec-minimal")))]
pub type Spec = GnosisEthSpec;

#[cfg(test)]
mod test {
    use super::Spec;
    use crate::{EthSpec, EthSpecId, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};

    /// `Spec` must follow the preset feature this build was compiled with.
    #[test]
    fn spec_follows_feature() {
        let expected = if cfg!(feature = "spec-minimal") {
            EthSpecId::Minimal
        } else if cfg!(feature = "spec-gnosis") {
            EthSpecId::Gnosis
        } else {
            EthSpecId::Mainnet
        };
        assert_eq!(Spec::spec_name(), expected);
    }

    macro_rules! assert_valid {
        ($spec:ident) => {{
            let spec = $spec::default_spec();

            const {
                assert!(
                    $spec::MAX_VALIDATORS_PER_SLOT >= $spec::MAX_VALIDATORS_PER_COMMITTEE,
                    "MAX_VALIDATORS_PER_SLOT must be >= MAX_VALIDATORS_PER_COMMITTEE",
                );

                // The derived values must match what they are derived from.
                assert!(
                    $spec::MAX_PENDING_ATTESTATIONS
                        == $spec::MAX_ATTESTATIONS * $spec::SLOTS_PER_EPOCH
                );
                assert!(
                    $spec::SLOTS_PER_ETH1_VOTING_PERIOD
                        == $spec::EPOCHS_PER_ETH1_VOTING_PERIOD * $spec::SLOTS_PER_EPOCH
                );
                assert!(
                    $spec::SYNC_SUBCOMMITTEE_SIZE
                        == $spec::SYNC_COMMITTEE_SIZE / $spec::SYNC_COMMITTEE_SUBNET_COUNT
                );
                assert!(
                    $spec::BYTES_PER_BLOB
                        == $spec::BYTES_PER_FIELD_ELEMENT * $spec::FIELD_ELEMENTS_PER_BLOB
                );
                assert!(
                    $spec::BYTES_PER_CELL
                        == $spec::BYTES_PER_FIELD_ELEMENT * $spec::FIELD_ELEMENTS_PER_CELL
                );
                assert!(
                    $spec::MAX_CELLS_PER_BLOCK
                        == $spec::FIELD_ELEMENTS_PER_EXT_BLOB
                            * $spec::MAX_BLOB_COMMITMENTS_PER_BLOCK
                );
                assert!($spec::BUILDER_PENDING_PAYMENTS_LIMIT == 2 * $spec::SLOTS_PER_EPOCH);
            }

            assert_eq!(
                $spec::PROPOSER_LOOKAHEAD_SLOTS,
                (spec.min_seed_lookahead.as_usize() + 1) * $spec::SLOTS_PER_EPOCH,
                "PROPOSER_LOOKAHEAD_SLOTS must equal (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH"
            );

            assert_eq!(
                $spec::PTC_WINDOW_LENGTH,
                (spec.min_seed_lookahead.as_usize() + 2) * $spec::SLOTS_PER_EPOCH,
                "PTC_WINDOW_LENGTH must equal (2 + MIN_SEED_LOOKAHEAD) * SLOTS_PER_EPOCH"
            );
        }};
    }

    #[test]
    fn assert_valid_spec() {
        assert_valid!(MainnetEthSpec);
        assert_valid!(MinimalEthSpec);
        assert_valid!(GnosisEthSpec);
    }
}
