//! Production-backed runner for consensus-specs v1.7.0-alpha.14 light_client/sync.
//!
//! Format: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/tests/formats/light_client/sync.md

use super::*;
use alloy_primitives::FixedBytes;
use decentralized_checkpoint_sync::{
    LightClientStore, LightClientStoreSchema, LightClientSyncError, beacon_header,
    initialize_light_client_store, process_light_client_store_force_update,
    process_light_client_update, upgrade_light_client_bootstrap, upgrade_light_client_store,
    upgrade_light_client_update, validate_light_client_update,
};
use serde::Deserialize;
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{
    Config, ExecutionPayloadHeaderCapella, Hash256, LightClientBootstrap, LightClientHeader, Slot,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    genesis_validators_root: Hash256,
    trusted_block_root: Hash256,
    bootstrap_fork_digest: FixedBytes<4>,
    store_fork_version: FixedBytes<4>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Step {
    ProcessUpdate { process_update: ProcessUpdate },
    ForceUpdate { force_update: ForceUpdate },
    UpgradeStore { upgrade_store: UpgradeStore },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessUpdate {
    update_fork_digest: FixedBytes<4>,
    update: String,
    current_slot: Slot,
    checks: Checks,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForceUpdate {
    current_slot: Slot,
    checks: Checks,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpgradeStore {
    store_fork_version: FixedBytes<4>,
    checks: Checks,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checks {
    finalized_header: HeaderChecks,
    optimistic_header: HeaderChecks,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderChecks {
    slot: Slot,
    beacon_root: Hash256,
    execution_root: Option<Hash256>,
}

#[derive(Debug)]
pub struct LightClientSync<E: EthSpec> {
    path: PathBuf,
    spec: ChainSpec,
    metadata: Metadata,
    steps: Vec<Step>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for LightClientSync<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        // A directory's fork is NOT the complete schedule: vectors can upgrade the store
        // before activation, cross multiple forks, and change Fulu blob parameters.
        let config: Config = decode::yaml_decode_file(&path.join("config.yaml"))?;
        let spec = ChainSpec::from_config::<E>(&config).ok_or_else(|| {
            Error::FailedToParseTest("light-client config has an incompatible preset".into())
        })?;
        Ok(Self {
            path: path.into(),
            spec,
            metadata: decode::yaml_decode_file(&path.join("meta.yaml"))?,
            steps: decode::yaml_decode_file(&path.join("steps.yaml"))?,
            _phantom: PhantomData,
        })
    }
}

impl<E: EthSpec> Case for LightClientSync<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        LightClientStoreSchema::try_from(fork_name).is_ok()
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let (mut store, mut store_fork) = self.initialize_store()?;
        for (index, step) in self.steps.iter().enumerate() {
            self.execute_step(step, &mut store, &mut store_fork)
                .map_err(|error| {
                    Error::InternalError(format!("light-client step {index}: {error:?}"))
                })?;
        }
        Ok(())
    }
}

impl<E: EthSpec> LightClientSync<E> {
    fn initialize_store(&self) -> Result<(LightClientStore<E>, ForkName), Error> {
        let spec = &self.spec;
        let store_fork = fork_for_version(self.metadata.store_fork_version, spec)?;
        let store_schema = LightClientStoreSchema::try_from(store_fork).map_err(sync_error)?;
        let bootstrap_fork = fork_for_digest(
            self.metadata.bootstrap_fork_digest,
            self.metadata.genesis_validators_root,
            spec,
        )?;
        let bootstrap =
            decode::ssz_decode_file_with(&self.path.join("bootstrap.ssz_snappy"), |bytes| {
                LightClientBootstrap::<E>::from_ssz_bytes(bytes, bootstrap_fork)
            })?;
        check_digest_at_slot::<E>(
            self.metadata.bootstrap_fork_digest,
            bootstrap.get_slot(),
            self.metadata.genesis_validators_root,
            spec,
        )?;
        // Bellatrix uses Altair's store version and Fulu uses Electra's. Preserve a newer
        // wire variant when the schemas match, rather than attempting a backwards conversion.
        let bootstrap_format = store_fork.max(bootstrap_fork);
        let bootstrap =
            upgrade_light_client_bootstrap(&bootstrap, bootstrap_format).map_err(sync_error)?;
        let store = initialize_light_client_store(
            self.metadata.trusted_block_root,
            &bootstrap,
            bootstrap_format,
            store_schema,
            spec,
        )
        .map_err(sync_error)?;

        Ok((store, store_fork))
    }

    fn execute_step(
        &self,
        step: &Step,
        store: &mut LightClientStore<E>,
        store_fork: &mut ForkName,
    ) -> Result<(), Error> {
        let spec = &self.spec;
        let checks = match step {
            Step::ProcessUpdate {
                process_update: step,
            } => {
                let data_fork = fork_for_digest(
                    step.update_fork_digest,
                    self.metadata.genesis_validators_root,
                    spec,
                )?;
                let path = update_path(&self.path, &step.update)?;
                let update = decode::ssz_decode_light_client_update::<E>(&path, &data_fork)?;
                check_digest_at_slot::<E>(
                    step.update_fork_digest,
                    update.attested_header_slot(),
                    self.metadata.genesis_validators_root,
                    spec,
                )?;
                let format = (*store_fork).max(data_fork);
                let update = upgrade_light_client_update(&update, format).map_err(sync_error)?;
                // All process_update steps in this format are valid; do not swallow failures.
                validate_light_client_update(
                    store,
                    &update,
                    format,
                    step.current_slot,
                    self.metadata.genesis_validators_root,
                    spec,
                )
                .and_then(process_light_client_update)
                .map_err(sync_error)?;
                &step.checks
            }
            Step::ForceUpdate { force_update: step } => {
                let checkpoint = store.verified_checkpoint_header().clone();
                process_light_client_store_force_update(store, step.current_slot, spec)
                    .map_err(sync_error)?;
                if store.verified_checkpoint_header() != &checkpoint {
                    return Err(Error::NotEqual(
                        "force update changed the verified checkpoint".into(),
                    ));
                }
                &step.checks
            }
            Step::UpgradeStore {
                upgrade_store: step,
            } => {
                let fork = fork_for_version(step.store_fork_version, spec)?;
                upgrade_light_client_store(store, fork).map_err(sync_error)?;
                *store_fork = fork;
                &step.checks
            }
        };
        // EF finalized_header is SPEC state, not our independently authenticated checkpoint.
        checks
            .finalized_header
            .check(store.spec_finalized_header(), spec, "finalized_header")?;
        checks
            .optimistic_header
            .check(store.optimistic_header(), spec, "optimistic_header")
    }
}

fn sync_error(error: LightClientSyncError) -> Error {
    Error::InternalError(format!("light-client operation failed: {error:?}"))
}

fn fork_for_version(version: FixedBytes<4>, spec: &ChainSpec) -> Result<ForkName, Error> {
    let mut forks = ForkName::list_all()
        .into_iter()
        .filter(|fork| spec.fork_version_for_name(*fork) == version.0);
    let fork = forks
        .next()
        .ok_or_else(|| Error::FailedToParseTest(format!("unknown store fork version {version}")))?;
    // Config uses a shared placeholder for omitted future versions. It must not be
    // interpreted as the first matching fork and silently select a supported schema.
    if forks.next().is_some() {
        return Err(Error::FailedToParseTest(format!(
            "ambiguous store fork version {version}"
        )));
    }
    Ok(fork)
}

fn fork_for_digest(
    digest: FixedBytes<4>,
    genesis_root: Hash256,
    spec: &ChainSpec,
) -> Result<ForkName, Error> {
    // Include every blob-parameter epoch, not just fork activations. Fulu can have several
    // distinct digests for the same SSZ data format within a single test case.
    spec.all_digest_epochs()
        .find(|epoch| spec.compute_fork_digest(genesis_root, *epoch) == digest.0)
        .map(|epoch| spec.fork_name_at_epoch(epoch))
        .ok_or_else(|| {
            Error::FailedToParseTest(format!("unknown light-client fork digest {digest}"))
        })
}

fn update_path(directory: &Path, name: &str) -> Result<PathBuf, Error> {
    // A vector names a single SSZ file stem, not an arbitrary filesystem path.
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(Error::FailedToParseTest(format!(
            "invalid light-client update filename {name:?}"
        )));
    }
    Ok(directory.join(format!("{name}.ssz_snappy")))
}

fn check_digest_at_slot<E: EthSpec>(
    digest: FixedBytes<4>,
    slot: Slot,
    genesis_root: Hash256,
    spec: &ChainSpec,
) -> Result<(), Error> {
    if spec.compute_fork_digest(genesis_root, slot.epoch(E::slots_per_epoch())) != digest.0 {
        return Err(Error::FailedToParseTest(format!(
            "fork digest {digest} does not match data slot {slot}"
        )));
    }
    Ok(())
}

impl HeaderChecks {
    fn check<E: EthSpec>(
        &self,
        header: &LightClientHeader<E>,
        spec: &ChainSpec,
        field: &str,
    ) -> Result<(), Error> {
        let beacon = beacon_header(header);
        if self.execution_root.is_some() == matches!(header, LightClientHeader::Altair(_)) {
            return Err(Error::FailedToParseTest(format!(
                "{field}: execution_root check does not match the store's data format"
            )));
        }
        if beacon.slot != self.slot || beacon.canonical_root() != self.beacon_root {
            return Err(Error::NotEqual(format!(
                "{field}: expected slot {} root {:?}, got slot {} root {:?}",
                self.slot,
                self.beacon_root,
                beacon.slot,
                beacon.canonical_root(),
            )));
        }
        if let Some(expected) = self.execution_root {
            let actual = execution_root(header, spec)?;
            if actual != expected {
                return Err(Error::NotEqual(format!(
                    "{field}.execution_root: expected {expected:?}, got {actual:?}"
                )));
            }
        }
        Ok(())
    }
}

/// The spec's get_lc_execution_root uses the HEADER SLOT's fork, not its upgraded SSZ layout.
fn execution_root<E: EthSpec>(
    header: &LightClientHeader<E>,
    spec: &ChainSpec,
) -> Result<Hash256, Error> {
    let fork = spec.fork_name_at_slot::<E>(beacon_header(header).slot);
    if !fork.capella_enabled() {
        return Ok(Hash256::default());
    }
    macro_rules! root {
        ($execution:expr) => {{
            let execution = $execution;
            if fork.deneb_enabled() {
                execution.tree_hash_root()
            } else {
                ExecutionPayloadHeaderCapella::<E> {
                    parent_hash: execution.parent_hash,
                    fee_recipient: execution.fee_recipient,
                    state_root: execution.state_root,
                    receipts_root: execution.receipts_root,
                    logs_bloom: execution.logs_bloom.clone(),
                    prev_randao: execution.prev_randao,
                    block_number: execution.block_number,
                    gas_limit: execution.gas_limit,
                    gas_used: execution.gas_used,
                    timestamp: execution.timestamp,
                    extra_data: execution.extra_data.clone(),
                    base_fee_per_gas: execution.base_fee_per_gas,
                    block_hash: execution.block_hash,
                    transactions_root: execution.transactions_root,
                    withdrawals_root: execution.withdrawals_root,
                }
                .tree_hash_root()
            }
        }};
    }
    Ok(match header {
        LightClientHeader::Altair(_) => {
            return Err(Error::InternalError(
                "post-Capella slot in an Altair header".into(),
            ));
        }
        LightClientHeader::Capella(inner) => inner.execution.tree_hash_root(),
        LightClientHeader::Deneb(inner) => root!(&inner.execution),
        LightClientHeader::Electra(inner) => root!(&inner.execution),
        LightClientHeader::Fulu(inner) => root!(&inner.execution),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{Handler, LightClientSyncHandler};
    use decentralized_checkpoint_sync::upgrade_light_client_header;
    use types::{
        BlobParameters, Epoch, LightClientHeaderAltair, LightClientHeaderCapella, MinimalEthSpec,
    };

    type E = MinimalEthSpec;

    #[test]
    fn handler_enables_supported_forks_with_either_crypto_backend() {
        let handler = LightClientSyncHandler::<E>::default();
        assert_eq!(
            handler.disabled_forks(),
            vec![ForkName::Gloas, ForkName::Heze]
        );
        for fork in ForkName::list_all() {
            assert_eq!(
                handler.is_enabled_for_fork(fork),
                matches!(
                    fork,
                    ForkName::Altair
                        | ForkName::Bellatrix
                        | ForkName::Capella
                        | ForkName::Deneb
                        | ForkName::Electra
                        | ForkName::Fulu
                ),
                "{fork}"
            );
        }
    }

    #[test]
    fn handler_disables_only_named_unsupported_formats() {
        let handler = LightClientSyncHandler::<E>::default();
        for fork in [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
        ] {
            for (name, disabled) in [
                ("gloas_store_with_legacy_data", true),
                ("deneb_gloas_fork", fork == ForkName::Capella),
                ("electra_gloas_fork", fork == ForkName::Deneb),
                ("gloas_fork", fork == ForkName::Fulu),
                ("light_client_sync", false),
                ("new_case", false),
                ("new_gloas_case", false),
            ] {
                assert_eq!(
                    handler.is_enabled_for_case(Path::new(name), fork),
                    !disabled,
                    "{fork}/{name}"
                );
            }
        }
    }

    #[test]
    fn fork_versions_are_not_fork_digests_and_unknown_contexts_fail() {
        let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
        let genesis_root = Hash256::repeat_byte(1);
        let version = FixedBytes(spec.altair_fork_version);
        let digest = FixedBytes(spec.compute_fork_digest(genesis_root, Epoch::new(0)));
        assert_eq!(fork_for_version(version, &spec).unwrap(), ForkName::Altair);
        assert_eq!(
            fork_for_digest(digest, genesis_root, &spec).unwrap(),
            ForkName::Altair
        );
        assert!(fork_for_version(digest, &spec).is_err());
        assert!(fork_for_digest(version, genesis_root, &spec).is_err());
        assert!(fork_for_version(FixedBytes::repeat_byte(255), &spec).is_err());
        assert!(fork_for_digest(FixedBytes::repeat_byte(255), genesis_root, &spec).is_err());
        assert!(fork_for_digest(digest, Hash256::repeat_byte(2), &spec).is_err());

        let mut spec = spec;
        spec.gloas_fork_version = spec.altair_fork_version;
        assert!(fork_for_version(version, &spec).is_err());
    }

    #[test]
    fn fulu_blob_schedule_digests_resolve_to_the_same_data_fork() {
        let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        spec.blob_schedule = types::BlobSchedule::new(vec![
            BlobParameters {
                epoch: Epoch::new(5),
                max_blobs_per_block: 10,
            },
            BlobParameters {
                epoch: Epoch::new(10),
                max_blobs_per_block: 20,
            },
        ]);
        let root = Hash256::repeat_byte(1);
        let first = FixedBytes(spec.compute_fork_digest(root, Epoch::new(5)));
        let second = FixedBytes(spec.compute_fork_digest(root, Epoch::new(10)));
        assert_ne!(first, second);
        for digest in [first, second] {
            assert_eq!(
                fork_for_digest(digest, root, &spec).unwrap(),
                ForkName::Fulu
            );
        }
        check_digest_at_slot::<E>(second, Slot::new(80), root, &spec).unwrap();
        assert!(check_digest_at_slot::<E>(first, Slot::new(80), root, &spec).is_err());
        assert_eq!(
            fork_for_version(FixedBytes(spec.electra_fork_version), &spec).unwrap(),
            ForkName::Electra
        );
    }

    #[test]
    fn parser_rejects_unknown_steps_checks_and_missing_required_fields() {
        assert!(decode::yaml_decode::<Vec<Step>>("- unknown_step: {}").is_err());
        assert!(decode::yaml_decode::<Vec<Step>>("- force_update: {current_slot: 10}").is_err());
        let valid_checks = format!("slot: 1\nbeacon_root: '{:?}'\n", Hash256::default());
        assert!(decode::yaml_decode::<HeaderChecks>(&valid_checks).is_ok());
        assert!(
            decode::yaml_decode::<HeaderChecks>(&format!("{valid_checks}unknown: 2\n")).is_err()
        );
        assert!(decode::yaml_decode::<Metadata>("genesis_validators_root: '0x01'").is_err());
    }

    #[test]
    fn update_file_names_cannot_escape_the_case_directory() {
        let directory = Path::new("case");
        assert_eq!(
            update_path(directory, "update_0x123_sf").unwrap(),
            directory.join("update_0x123_sf.ssz_snappy")
        );
        for name in ["", ".", "..", "../update", "/tmp/update", "a/b", "a\\b"] {
            assert!(update_path(directory, name).is_err());
        }
    }

    #[test]
    fn header_checks_detect_slot_beacon_and_execution_root_mismatches() {
        let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
        let header = LightClientHeader::Capella(LightClientHeaderCapella::<E>::default());
        let make_checks = || HeaderChecks {
            slot: Slot::new(0),
            beacon_root: beacon_header(&header).canonical_root(),
            execution_root: Some(execution_root(&header, &spec).unwrap()),
        };
        make_checks().check(&header, &spec, "header").unwrap();
        let mut checks = make_checks();
        checks.slot = Slot::new(1);
        assert!(checks.check(&header, &spec, "header").is_err());
        let mut checks = make_checks();
        checks.beacon_root = Hash256::repeat_byte(1);
        assert!(checks.check(&header, &spec, "header").is_err());
        let mut checks = make_checks();
        checks.execution_root = Some(Hash256::repeat_byte(2));
        assert!(checks.check(&header, &spec, "header").is_err());
        let mut checks = make_checks();
        checks.execution_root = None;
        assert!(checks.check(&header, &spec, "header").is_err());
    }

    #[test]
    fn execution_root_uses_historical_slot_not_upgraded_representation() {
        let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
        let header = LightClientHeader::Capella(LightClientHeaderCapella::<E>::default());
        let expected = execution_root(&header, &spec).unwrap();
        let upgraded = upgrade_light_client_header(&header, ForkName::Fulu).unwrap();
        assert_eq!(execution_root(&upgraded, &spec).unwrap(), expected);
        let LightClientHeader::Fulu(inner) = &upgraded else {
            unreachable!()
        };
        assert_ne!(inner.execution.tree_hash_root(), expected);

        let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
        let header = LightClientHeader::Altair(LightClientHeaderAltair::<E>::default());
        let upgraded = upgrade_light_client_header(&header, ForkName::Fulu).unwrap();
        assert_eq!(
            execution_root(&upgraded, &spec).unwrap(),
            Hash256::default()
        );
    }
}

// These fault-injection tests use official fixtures, so they require the same opt-in as
// the conformance handler. Only the in-memory case is modified, never the downloaded files.
#[cfg(all(test, feature = "ef_tests"))]
mod conformance_tests {
    use super::*;
    use types::{Epoch, MinimalEthSpec};

    type E = MinimalEthSpec;

    fn load_case(fork: ForkName, name: &str) -> LightClientSync<E> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("consensus-spec-tests/tests/minimal")
            .join(fork.to_string())
            .join("light_client/sync/pyspec_tests")
            .join(name);
        LightClientSync::load_from_dir(&path, fork).unwrap()
    }

    fn assert_failure(result: Result<(), Error>, expected: &str) {
        let error = result.unwrap_err();
        assert!(!error.is_skipped(), "{error:?}");
        assert!(error.message().contains(expected), "{error:?}");
    }

    #[test]
    fn bootstrap_errors_fail_the_case() {
        let mut case = load_case(ForkName::Altair, "light_client_sync");
        case.metadata.trusted_block_root = Hash256::repeat_byte(255);
        assert_failure(case.result(0, ForkName::Altair), "BootstrapRootMismatch");
    }

    #[test]
    fn process_errors_fail_the_case_without_mutating_store() {
        let mut case = load_case(ForkName::Altair, "light_client_sync");
        let (mut store, mut fork) = case.initialize_store().unwrap();
        let before = format!("{store:?}");
        let step = case.steps.first_mut().unwrap();
        let Step::ProcessUpdate { process_update } = step else {
            panic!("fixture must start with process_update");
        };
        process_update.current_slot = Slot::new(0);
        assert_failure(
            case.execute_step(case.steps.first().unwrap(), &mut store, &mut fork),
            "InvalidUpdateSlots",
        );
        assert_eq!(format!("{store:?}"), before);
        assert_failure(case.result(0, ForkName::Altair), "light-client step 0");
    }

    #[test]
    fn force_errors_propagate_without_mutating_store() {
        let mut case = load_case(ForkName::Altair, "light_client_sync");
        let (mut store, mut fork) = case.initialize_store().unwrap();
        let force_index = case
            .steps
            .iter()
            .position(|step| matches!(step, Step::ForceUpdate { .. }))
            .unwrap();
        for step in case.steps.iter().take(force_index) {
            case.execute_step(step, &mut store, &mut fork).unwrap();
        }
        assert!(store.best_valid_update().is_some());
        let before = format!("{store:?}");
        case.spec.epochs_per_sync_committee_period = Epoch::new(0);
        assert_failure(
            case.execute_step(case.steps.get(force_index).unwrap(), &mut store, &mut fork),
            "Arithmetic",
        );
        assert_eq!(format!("{store:?}"), before);
    }

    #[test]
    fn unsupported_bootstrap_and_upgrade_are_errors_not_skips() {
        for unsupported in [ForkName::Gloas, ForkName::Heze] {
            let mut case = load_case(ForkName::Altair, "light_client_sync");
            // Altair's config omits future versions, which share Config's placeholder
            // 0xffffffff. Give the injected targets distinct versions.
            case.spec.gloas_fork_version = [7, 0, 0, 1];
            case.spec.heze_fork_version = [8, 0, 0, 1];
            let (mut store, mut fork) = case.initialize_store().unwrap();
            let before = format!("{store:?}");
            let version = FixedBytes(case.spec.fork_version_for_name(unsupported));
            let Step::ProcessUpdate { process_update } = case.steps.remove(0) else {
                panic!("fixture must start with process_update");
            };
            case.steps = vec![Step::UpgradeStore {
                upgrade_store: UpgradeStore {
                    store_fork_version: version,
                    checks: process_update.checks,
                },
            }];
            assert_failure(
                case.execute_step(case.steps.first().unwrap(), &mut store, &mut fork),
                "UnsupportedFork",
            );
            assert_eq!(format!("{store:?}"), before);
            assert_eq!(fork, ForkName::Altair);
            assert_failure(case.result(0, ForkName::Altair), "UnsupportedFork");
            case.metadata.store_fork_version = version;
            assert_failure(case.result(0, ForkName::Altair), "UnsupportedFork");
        }
    }

    #[test]
    fn both_headers_are_checked_after_every_step_kind() {
        for name in ["light_client_sync", "deneb_fork"] {
            let original = load_case(ForkName::Capella, name);
            original.result(0, ForkName::Capella).unwrap();
            for index in 0..original.steps.len() {
                for field in ["finalized_header", "optimistic_header"] {
                    let mut case = load_case(ForkName::Capella, name);
                    let checks = match case.steps.get_mut(index).unwrap() {
                        Step::ProcessUpdate { process_update } => &mut process_update.checks,
                        Step::ForceUpdate { force_update } => &mut force_update.checks,
                        Step::UpgradeStore { upgrade_store } => &mut upgrade_store.checks,
                    };
                    let header = if field == "finalized_header" {
                        &mut checks.finalized_header
                    } else {
                        &mut checks.optimistic_header
                    };
                    header.beacon_root = Hash256::repeat_byte(255);
                    let error = case.result(0, ForkName::Capella).unwrap_err();
                    assert!(!error.is_skipped());
                    assert!(
                        error
                            .message()
                            .contains(&format!("light-client step {index}:"))
                    );
                    assert!(error.message().contains(field), "{error:?}");
                }
            }
        }
    }
}
