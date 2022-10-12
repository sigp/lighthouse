use crate::cases::{self, Case, Cases, EpochTransition, LoadCase, Operation};
use crate::type_name;
use crate::type_name::TypeName;
use derivative::Derivative;
use std::fs::{self, DirEntry};
use std::marker::PhantomData;
use std::path::PathBuf;
use types::{BeaconState, EthSpec, ForkName};

pub trait Handler {
    type Case: Case + LoadCase;

    fn config_name() -> &'static str {
        "general"
    }

    fn runner_name() -> &'static str;

    fn handler_name(&self) -> String;

    fn is_enabled_for_fork(&self, fork_name: ForkName) -> bool {
        Self::Case::is_enabled_for_fork(fork_name)
    }

    fn run(&self) {
        for fork_name in ForkName::list_all() {
            if self.is_enabled_for_fork(fork_name) {
                self.run_for_fork(fork_name)
            }
        }
    }

    fn use_rayon() -> bool {
        true
    }

    fn run_for_fork(&self, fork_name: ForkName) {
        let fork_name_str = fork_name.to_string();

        let handler_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("consensus-spec-tests")
            .join("tests")
            .join(Self::config_name())
            .join(&fork_name_str)
            .join(Self::runner_name())
            .join(self.handler_name());

        // Iterate through test suites
        let as_directory = |entry: Result<DirEntry, std::io::Error>| -> Option<DirEntry> {
            entry
                .ok()
                .filter(|e| e.file_type().map(|ty| ty.is_dir()).unwrap())
        };

        let test_cases = fs::read_dir(&handler_path)
            .unwrap_or_else(|e| panic!("handler dir {} exists: {:?}", handler_path.display(), e))
            .filter_map(as_directory)
            .flat_map(|suite| fs::read_dir(suite.path()).expect("suite dir exists"))
            .filter_map(as_directory)
            .map(|test_case_dir| {
                let path = test_case_dir.path();

                let case = Self::Case::load_from_dir(&path, fork_name).expect("test should load");
                (path, case)
            })
            .collect();

        let results = Cases { test_cases }.test_results(fork_name, Self::use_rayon());

        let name = format!(
            "{}/{}/{}",
            fork_name_str,
            Self::runner_name(),
            self.handler_name()
        );
        crate::results::assert_tests_pass(&name, &handler_path, &results);
    }
}

macro_rules! bls_eth_handler {
    ($runner_name: ident, $case_name:ident, $handler_name:expr) => {
        #[derive(Derivative)]
        #[derivative(Default(bound = ""))]
        pub struct $runner_name;

        impl Handler for $runner_name {
            type Case = cases::$case_name;

            fn runner_name() -> &'static str {
                "bls"
            }

            fn handler_name(&self) -> String {
                $handler_name.into()
            }
        }
    };
}

macro_rules! bls_handler {
    ($runner_name: ident, $case_name:ident, $handler_name:expr) => {
        #[derive(Derivative)]
        #[derivative(Default(bound = ""))]
        pub struct $runner_name;

        impl Handler for $runner_name {
            type Case = cases::$case_name;

            fn runner_name() -> &'static str {
                "bls"
            }

            fn config_name() -> &'static str {
                "bls12-381-tests"
            }

            fn handler_name(&self) -> String {
                $handler_name.into()
            }

            fn run(&self) {
                let fork_name = ForkName::Base;
                let fork_name_str = fork_name.to_string();
                let handler_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("consensus-spec-tests")
                    .join(Self::config_name())
                    .join(self.handler_name());

                let as_file = |entry: Result<DirEntry, std::io::Error>| -> Option<DirEntry> {
                    entry
                        .ok()
                        .filter(|e| e.file_type().map(|ty| ty.is_file()).unwrap_or(false))
                };
                let test_cases: Vec<(PathBuf, Self::Case)> = fs::read_dir(&handler_path)
                    .expect("handler dir exists")
                    .filter_map(as_file)
                    .map(|test_case_path| {
                        let path = test_case_path.path();
                        let case =
                            Self::Case::load_from_dir(&path, fork_name).expect("test should load");

                        (path, case)
                    })
                    .collect();

                let results = Cases { test_cases }.test_results(fork_name, Self::use_rayon());

                let name = format!(
                    "{}/{}/{}",
                    fork_name_str,
                    Self::runner_name(),
                    self.handler_name()
                );
                crate::results::assert_tests_pass(&name, &handler_path, &results);
            }
        }
    };
}

bls_handler!(BlsAggregateSigsHandler, BlsAggregateSigs, "aggregate");
bls_handler!(BlsSignMsgHandler, BlsSign, "sign");
bls_handler!(BlsBatchVerifyHandler, BlsBatchVerify, "batch_verify");
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
bls_eth_handler!(
    BlsEthAggregatePubkeysHandler,
    BlsEthAggregatePubkeys,
    "eth_aggregate_pubkeys"
);
bls_eth_handler!(
    BlsEthFastAggregateVerifyHandler,
    BlsEthFastAggregateVerify,
    "eth_fast_aggregate_verify"
);

/// Handler for SSZ types.
pub struct SszStaticHandler<T, E> {
    supported_forks: Vec<ForkName>,
    _phantom: PhantomData<(T, E)>,
}

impl<T, E> Default for SszStaticHandler<T, E> {
    fn default() -> Self {
        Self::for_forks(ForkName::list_all())
    }
}

impl<T, E> SszStaticHandler<T, E> {
    pub fn for_forks(supported_forks: Vec<ForkName>) -> Self {
        SszStaticHandler {
            supported_forks,
            _phantom: PhantomData,
        }
    }

    pub fn base_only() -> Self {
        Self::for_forks(vec![ForkName::Base])
    }

    pub fn altair_only() -> Self {
        Self::for_forks(vec![ForkName::Altair])
    }

    pub fn altair_and_later() -> Self {
        Self::for_forks(ForkName::list_all()[1..].to_vec())
    }

    pub fn merge_only() -> Self {
        Self::for_forks(vec![ForkName::Merge])
    }

    pub fn merge_and_later() -> Self {
        Self::for_forks(ForkName::list_all()[2..].to_vec())
    }
}

/// Handler for SSZ types that implement `CachedTreeHash`.
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct SszStaticTHCHandler<T, E>(PhantomData<(T, E)>);

/// Handler for SSZ types that don't implement `ssz::Decode`.
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct SszStaticWithSpecHandler<T, E>(PhantomData<(T, E)>);

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

    fn handler_name(&self) -> String {
        T::name().into()
    }

    fn is_enabled_for_fork(&self, fork_name: ForkName) -> bool {
        self.supported_forks.contains(&fork_name)
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

    fn handler_name(&self) -> String {
        BeaconState::<E>::name().into()
    }
}

impl<T, E> Handler for SszStaticWithSpecHandler<T, E>
where
    T: TypeName,
    E: EthSpec + TypeName,
    cases::SszStaticWithSpec<T>: Case + LoadCase,
{
    type Case = cases::SszStaticWithSpec<T>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "ssz_static"
    }

    fn handler_name(&self) -> String {
        T::name().into()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct ShufflingHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for ShufflingHandler<E> {
    type Case = cases::Shuffling<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "shuffling"
    }

    fn handler_name(&self) -> String {
        "core".into()
    }

    fn is_enabled_for_fork(&self, fork_name: ForkName) -> bool {
        fork_name == ForkName::Base
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct SanityBlocksHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for SanityBlocksHandler<E> {
    type Case = cases::SanityBlocks<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "sanity"
    }

    fn handler_name(&self) -> String {
        "blocks".into()
    }

    fn is_enabled_for_fork(&self, _fork_name: ForkName) -> bool {
        // NOTE: v1.1.0-beta.4 doesn't mark the historical blocks test as requiring real crypto, so
        // only run these tests with real crypto for now.
        cfg!(not(feature = "fake_crypto"))
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct SanitySlotsHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for SanitySlotsHandler<E> {
    type Case = cases::SanitySlots<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "sanity"
    }

    fn handler_name(&self) -> String {
        "slots".into()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct RandomHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for RandomHandler<E> {
    type Case = cases::SanityBlocks<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "random"
    }

    fn handler_name(&self) -> String {
        "random".into()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct EpochProcessingHandler<E, T>(PhantomData<(E, T)>);

impl<E: EthSpec + TypeName, T: EpochTransition<E>> Handler for EpochProcessingHandler<E, T> {
    type Case = cases::EpochProcessing<E, T>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "epoch_processing"
    }

    fn handler_name(&self) -> String {
        T::name().into()
    }
}

pub struct RewardsHandler<E: EthSpec> {
    handler_name: &'static str,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> RewardsHandler<E> {
    pub fn new(handler_name: &'static str) -> Self {
        Self {
            handler_name,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec + TypeName> Handler for RewardsHandler<E> {
    type Case = cases::RewardsTest<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "rewards"
    }

    fn handler_name(&self) -> String {
        self.handler_name.to_string()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct ForkHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for ForkHandler<E> {
    type Case = cases::ForkTest<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "fork"
    }

    fn handler_name(&self) -> String {
        "fork".into()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct TransitionHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for TransitionHandler<E> {
    type Case = cases::TransitionTest<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "transition"
    }

    fn handler_name(&self) -> String {
        "core".into()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
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

    fn handler_name(&self) -> String {
        "finality".into()
    }
}

pub struct ForkChoiceHandler<E> {
    handler_name: String,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> ForkChoiceHandler<E> {
    pub fn new(handler_name: &str) -> Self {
        Self {
            handler_name: handler_name.into(),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec + TypeName> Handler for ForkChoiceHandler<E> {
    type Case = cases::ForkChoiceTest<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "fork_choice"
    }

    fn handler_name(&self) -> String {
        self.handler_name.clone()
    }

    fn use_rayon() -> bool {
        // The fork choice tests use `block_on` which can cause panics with rayon.
        false
    }

    fn is_enabled_for_fork(&self, fork_name: ForkName) -> bool {
        // Merge block tests are only enabled for Bellatrix or later.
        if self.handler_name == "on_merge_block"
            && (fork_name == ForkName::Base || fork_name == ForkName::Altair)
        {
            return false;
        }

        // These tests check block validity (which may include signatures) and there is no need to
        // run them with fake crypto.
        cfg!(not(feature = "fake_crypto"))
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct GenesisValidityHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for GenesisValidityHandler<E> {
    type Case = cases::GenesisValidity<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "genesis"
    }

    fn handler_name(&self) -> String {
        "validity".into()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct GenesisInitializationHandler<E>(PhantomData<E>);

impl<E: EthSpec + TypeName> Handler for GenesisInitializationHandler<E> {
    type Case = cases::GenesisInitialization<E>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "genesis"
    }

    fn handler_name(&self) -> String {
        "initialization".into()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct OperationsHandler<E, O>(PhantomData<(E, O)>);

impl<E: EthSpec + TypeName, O: Operation<E>> Handler for OperationsHandler<E, O> {
    type Case = cases::Operations<E, O>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "operations"
    }

    fn handler_name(&self) -> String {
        O::handler_name()
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct SszGenericHandler<H>(PhantomData<H>);

impl<H: TypeName> Handler for SszGenericHandler<H> {
    type Case = cases::SszGeneric;

    fn config_name() -> &'static str {
        "general"
    }

    fn runner_name() -> &'static str {
        "ssz_generic"
    }

    fn is_enabled_for_fork(&self, fork_name: ForkName) -> bool {
        // SSZ generic tests are genesis only
        fork_name == ForkName::Base
    }

    fn handler_name(&self) -> String {
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
