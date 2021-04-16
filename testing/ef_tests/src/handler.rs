use crate::cases::{self, Case, Cases, EpochTransition, LoadCase, Operation};
use crate::type_name;
use crate::type_name::TypeName;
use cached_tree_hash::CachedTreeHash;
use std::fmt::Debug;
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use types::{BeaconState, EthSpec, ForkName};

pub trait Handler {
    type Case: Case + LoadCase;

    fn config_name() -> &'static str {
        "general"
    }

    fn runner_name() -> &'static str;

    fn handler_name() -> String;

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        Self::Case::is_enabled_for_fork(fork_name)
    }

    fn run() {
        for fork_name in ForkName::list_all() {
            if Self::is_enabled_for_fork(fork_name) {
                Self::run_for_fork(fork_name)
            }
        }
    }

    fn run_for_fork(fork_name: ForkName) {
        let fork_name_str = match fork_name {
            ForkName::Genesis => "phase0",
            ForkName::Altair => "altair",
        };

        let handler_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eth2.0-spec-tests")
            .join("tests")
            .join(Self::config_name())
            .join(fork_name_str)
            .join(Self::runner_name())
            .join(Self::handler_name());

        // Iterate through test suites
        let test_cases = fs::read_dir(&handler_path)
            .expect("handler dir exists")
            .flat_map(|entry| {
                entry
                    .ok()
                    .filter(|e| e.file_type().map(|ty| ty.is_dir()).unwrap_or(false))
            })
            .flat_map(|suite| fs::read_dir(suite.path()).expect("suite dir exists"))
            .flat_map(Result::ok)
            .map(|test_case_dir| {
                let path = test_case_dir.path();
                let case = Self::Case::load_from_dir(&path, fork_name).expect("test should load");
                (path, case)
            })
            .collect();

        let results = Cases { test_cases }.test_results(fork_name);

        let name = format!(
            "{}/{}/{}",
            fork_name_str,
            Self::runner_name(),
            Self::handler_name()
        );
        crate::results::assert_tests_pass(&name, &handler_path, &results);
    }
}

macro_rules! bls_handler {
    ($runner_name: ident, $case_name:ident, $handler_name:expr) => {
        pub struct $runner_name;

        impl Handler for $runner_name {
            type Case = cases::$case_name;

            fn is_enabled_for_fork(fork_name: ForkName) -> bool {
                fork_name == ForkName::Genesis
            }

            fn runner_name() -> &'static str {
                "bls"
            }

            fn handler_name() -> String {
                $handler_name.into()
            }
        }
    };
}

bls_handler!(BlsAggregateSigsHandler, BlsAggregateSigs, "aggregate");
bls_handler!(BlsSignMsgHandler, BlsSign, "sign");
bls_handler!(BlsVerifyMsgHandler, BlsVerify, "verify");
bls_handler!(
    BlsAggregateVerifyHandler,
    BlsAggregateVerify,
    "aggregate_verify"
);
bls_handler!(
    BlsFastAggregateVerifyHandler,
    BlsFastAggregateVerify,
    "fast_aggregate_verify"
);

/// Handler for SSZ types.
pub struct SszStaticHandler<T, E>(PhantomData<(T, E)>);

/// Handler for SSZ types that implement `CachedTreeHash`.
pub struct SszStaticTHCHandler<T, E>(PhantomData<(T, E)>);

impl<T, E> Handler for SszStaticHandler<T, E>
where
    T: cases::SszStaticType + ssz::Decode + TypeName,
    E: TypeName,
{
    type Case = cases::SszStatic<T>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "ssz_static"
    }

    fn handler_name() -> String {
        T::name().into()
    }
}

impl<E> Handler for SszStaticTHCHandler<BeaconState<E>, E>
where
    E: EthSpec + TypeName,
{
    type Case = cases::SszStaticTHC<BeaconState<E>>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "ssz_static"
    }

    fn handler_name() -> String {
        BeaconState::<E>::name().into()
    }
}

pub struct ShufflingHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for ShufflingHandler<E> {
    type Case = cases::Shuffling<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "shuffling"
    }

    fn handler_name() -> String {
        "core".into()
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Genesis
    }
}

pub struct SanityBlocksHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for SanityBlocksHandler<E> {
    type Case = cases::SanityBlocks<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "sanity"
    }

    fn handler_name() -> String {
        "blocks".into()
    }
}

pub struct SanitySlotsHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for SanitySlotsHandler<E> {
    type Case = cases::SanitySlots<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "sanity"
    }

    fn handler_name() -> String {
        "slots".into()
    }
}

pub struct EpochProcessingHandler<E, T>(PhantomData<(E, T)>);

impl<E: EthSpec + TypeName, T: EpochTransition<E>> Handler for EpochProcessingHandler<E, T> {
    type Case = cases::EpochProcessing<E, T>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "epoch_processing"
    }

    fn handler_name() -> String {
        T::name().into()
    }
}

pub struct FinalityHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for FinalityHandler<E> {
    // Reuse the blocks case runner.
    type Case = cases::SanityBlocks<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "finality"
    }

    fn handler_name() -> String {
        "finality".into()
    }
}

pub struct GenesisValidityHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for GenesisValidityHandler<E> {
    type Case = cases::GenesisValidity<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "genesis"
    }

    fn handler_name() -> String {
        "validity".into()
    }
}

pub struct GenesisInitializationHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for GenesisInitializationHandler<E> {
    type Case = cases::GenesisInitialization<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "genesis"
    }

    fn handler_name() -> String {
        "initialization".into()
    }
}

pub struct OperationsHandler<E, O>(PhantomData<(E, O)>);

impl<E: EthSpec + TypeName, O: Operation<E>> Handler for OperationsHandler<E, O> {
    type Case = cases::Operations<E, O>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "operations"
    }

    fn handler_name() -> String {
        O::handler_name()
    }
}

pub struct SszGenericHandler<H>(PhantomData<H>);

impl<H: TypeName> Handler for SszGenericHandler<H> {
    type Case = cases::SszGeneric;

    fn config_name() -> &'static str {
        "general"
    }

    fn runner_name() -> &'static str {
        "ssz_generic"
    }

    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        // SSZ generic tests are genesis only
        fork_name == ForkName::Genesis
    }

    fn handler_name() -> String {
        H::name().into()
    }
}

// Supported SSZ generic handlers
pub struct BasicVector;
type_name!(BasicVector, "basic_vector");
pub struct Bitlist;
type_name!(Bitlist, "bitlist");
pub struct Bitvector;
type_name!(Bitvector, "bitvector");
pub struct Boolean;
type_name!(Boolean, "boolean");
pub struct Uints;
type_name!(Uints, "uints");
pub struct Containers;
type_name!(Containers, "containers");
