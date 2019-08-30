use crate::cases::{self, Case, Cases, EpochTransition, LoadCase};
use crate::type_name::TypeName;
use crate::EfTest;
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use tree_hash::SignedRoot;
use types::EthSpec;

pub trait Handler {
    type Case: Case + LoadCase;

    fn config_name() -> &'static str {
        "general"
    }

    fn fork_name() -> &'static str {
        "phase0"
    }

    fn runner_name() -> &'static str;

    fn handler_name() -> &'static str;

    fn run() {
        let handler_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eth2.0-spec-tests")
            .join("tests")
            .join(Self::config_name())
            .join(Self::fork_name())
            .join(Self::runner_name())
            .join(Self::handler_name());

        // Iterate through test suites
        // TODO: parallelism
        // TODO: error handling?
        let test_cases = fs::read_dir(&handler_path)
            .expect("open main directory")
            .flat_map(|entry| {
                entry
                    .ok()
                    .filter(|e| e.file_type().map(|ty| ty.is_dir()).unwrap_or(false))
            })
            .flat_map(|suite| fs::read_dir(suite.path()).expect("open suite dir"))
            .flat_map(Result::ok)
            .map(|test_case_dir| Self::Case::load_from_dir(&test_case_dir.path()).expect("loads"))
            .collect::<Vec<_>>();

        let results = Cases { test_cases }.test_results();

        let name = format!("{}/{}", Self::runner_name(), Self::handler_name());
        crate::results::assert_tests_pass(&name, &handler_path, &results);
    }
}

macro_rules! bls_handler {
    ($runner_name: ident, $case_name:ident, $handler_name:expr) => {
        pub struct $runner_name;

        impl Handler for $runner_name {
            type Case = cases::$case_name;

            fn runner_name() -> &'static str {
                "bls"
            }

            fn handler_name() -> &'static str {
                $handler_name
            }
        }
    };
}

bls_handler!(
    BlsAggregatePubkeysHandler,
    BlsAggregatePubkeys,
    "aggregate_pubkeys"
);
bls_handler!(BlsAggregateSigsHandler, BlsAggregateSigs, "aggregate_sigs");
bls_handler!(
    BlsG2CompressedHandler,
    BlsG2Compressed,
    "msg_hash_compressed"
);
bls_handler!(BlsPrivToPubHandler, BlsPrivToPub, "priv_to_pub");
bls_handler!(BlsSignMsgHandler, BlsSign, "sign_msg");

/// Handler for SSZ types that do not implement `SignedRoot`.
pub struct SszStaticHandler<T, E>(PhantomData<(T, E)>);

/// Handler for SSZ types that do implement `SignedRoot`.
pub struct SszStaticSRHandler<T, E>(PhantomData<(T, E)>);

impl<T, E> Handler for SszStaticHandler<T, E>
where
    T: cases::SszStaticType + TypeName,
    E: TypeName,
{
    type Case = cases::SszStatic<T>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "ssz_static"
    }

    fn handler_name() -> &'static str {
        T::name()
    }
}

impl<T, E> Handler for SszStaticSRHandler<T, E>
where
    T: cases::SszStaticType + SignedRoot + TypeName,
    E: TypeName,
{
    type Case = cases::SszStaticSR<T>;

    fn config_name() -> &'static str {
        E::name()
    }

    fn runner_name() -> &'static str {
        "ssz_static"
    }

    fn handler_name() -> &'static str {
        T::name()
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

    fn handler_name() -> &'static str {
        "core"
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

    fn handler_name() -> &'static str {
        "blocks"
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

    fn handler_name() -> &'static str {
        "slots"
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

    fn handler_name() -> &'static str {
        T::name()
    }
}
