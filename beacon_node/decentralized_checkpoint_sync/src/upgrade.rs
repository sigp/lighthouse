//! Local representation upgrades, not validation or network decoding.
//!
//! Follows consensus-specs v1.7.0-alpha.14 [Capella], [Deneb], and [Electra] fork logic.
//! Fulu uses Electra's layout, but Lighthouse gives its objects distinct Rust enum variants.
//!
//! [Capella]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/capella/light-client/fork.md
//! [Deneb]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/deneb/light-client/fork.md
//! [Electra]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/electra/light-client/fork.md

use crate::{
    LightClientStoreSchema, LightClientSyncError, header::header_variant, update::UpdateView,
};
use types::{
    EthSpec, ForkName, Hash256, LightClientBootstrap, LightClientBootstrapAltair,
    LightClientBootstrapCapella, LightClientBootstrapDeneb, LightClientBootstrapElectra,
    LightClientBootstrapFulu, LightClientHeader, LightClientHeaderCapella, LightClientHeaderDeneb,
    LightClientHeaderElectra, LightClientHeaderFulu, LightClientUpdate, LightClientUpdateAltair,
    LightClientUpdateCapella, LightClientUpdateDeneb, LightClientUpdateElectra,
    LightClientUpdateFulu,
    light_client::consts::{
        CURRENT_SYNC_COMMITTEE_PROOF_LEN, CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA,
        FINALIZED_ROOT_PROOF_LEN, FINALIZED_ROOT_PROOF_LEN_ELECTRA, NEXT_SYNC_COMMITTEE_PROOF_LEN,
        NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA,
    },
};

/// Convert a header to a supported later data format without changing its beacon commitment.
///
/// This does not validate the input, prove finality, or recover missing execution data. Default
/// headers (including the genesis finality sentinel) remain default. Bellatrix uses Altair's
/// representation. Same-format calls are idempotent; backwards conversions are rejected,
/// including Fulu to Electra. The input is never modified.
pub fn upgrade_light_client_header<E: EthSpec>(
    header: &LightClientHeader<E>,
    target_fork: ForkName,
) -> Result<LightClientHeader<E>, LightClientSyncError> {
    LightClientStoreSchema::try_from(target_fork)?;
    let target_variant = if target_fork == ForkName::Bellatrix {
        ForkName::Altair
    } else {
        target_fork
    };
    let current = header_variant(header);
    if current > target_variant {
        return Err(LightClientSyncError::DataForkDowngrade {
            current,
            requested: target_fork,
        });
    }
    let mut upgraded = header.clone();
    while header_variant(&upgraded) < target_variant {
        upgraded = match upgraded {
            LightClientHeader::Altair(inner) => {
                LightClientHeader::Capella(LightClientHeaderCapella {
                    beacon: inner.beacon,
                    ..Default::default()
                })
            }
            LightClientHeader::Capella(inner) => LightClientHeader::Deneb(LightClientHeaderDeneb {
                beacon: inner.beacon,
                execution: inner.execution.upgrade_to_deneb(),
                execution_branch: inner.execution_branch,
                _phantom_data: inner._phantom_data,
            }),
            LightClientHeader::Deneb(inner) => {
                LightClientHeader::Electra(LightClientHeaderElectra {
                    beacon: inner.beacon,
                    execution: inner.execution.upgrade_to_electra(),
                    execution_branch: inner.execution_branch,
                    _phantom_data: inner._phantom_data,
                })
            }
            LightClientHeader::Electra(inner) => LightClientHeader::Fulu(LightClientHeaderFulu {
                beacon: inner.beacon,
                execution: inner.execution.upgrade_to_fulu(),
                execution_branch: inner.execution_branch,
                _phantom_data: inner._phantom_data,
            }),
            LightClientHeader::Fulu(inner) => return Ok(LightClientHeader::Fulu(inner)),
        };
    }
    Ok(upgraded)
}

/// Locally upgrade a bootstrap, preserving its committee and beacon commitment.
///
/// Electra adds zero padding at the START of the committee branch. Upgrading grants no trust:
/// the result must still pass [`crate::initialize_light_client_store`] against a trusted root.
/// Same-format calls do not add padding again. The input is never modified.
pub fn upgrade_light_client_bootstrap<E: EthSpec>(
    bootstrap: &LightClientBootstrap<E>,
    target_fork: ForkName,
) -> Result<LightClientBootstrap<E>, LightClientSyncError> {
    let target_schema = LightClientStoreSchema::try_from(target_fork)?;
    let (header, branch): (LightClientHeader<E>, &[Hash256]) = match bootstrap {
        LightClientBootstrap::Altair(inner) => (
            LightClientHeader::Altair(inner.header.clone()),
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Capella(inner) => (
            LightClientHeader::Capella(inner.header.clone()),
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Deneb(inner) => (
            LightClientHeader::Deneb(inner.header.clone()),
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Electra(inner) => (
            LightClientHeader::Electra(inner.header.clone()),
            inner.current_sync_committee_branch.as_ref(),
        ),
        LightClientBootstrap::Fulu(inner) => (
            LightClientHeader::Fulu(inner.header.clone()),
            inner.current_sync_committee_branch.as_ref(),
        ),
    };
    let header = upgrade_light_client_header(&header, target_fork)?;
    let depth = if target_schema == LightClientStoreSchema::Electra {
        CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA
    } else {
        CURRENT_SYNC_COMMITTEE_PROOF_LEN
    };
    let branch = normalize_branch(branch, depth)?;
    let branch_len = branch.len();
    macro_rules! upgraded {
        ($header:ident, $variant:ident, $type:ident) => {
            LightClientBootstrap::$variant($type {
                header: $header,
                current_sync_committee: bootstrap.current_sync_committee().clone(),
                current_sync_committee_branch: branch.try_into().map_err(|_| {
                    LightClientSyncError::InvalidUpgradeBranchLength {
                        actual: branch_len,
                        expected: depth,
                    }
                })?,
            })
        };
    }
    Ok(match header {
        LightClientHeader::Altair(inner) => upgraded!(inner, Altair, LightClientBootstrapAltair),
        LightClientHeader::Capella(inner) => upgraded!(inner, Capella, LightClientBootstrapCapella),
        LightClientHeader::Deneb(inner) => upgraded!(inner, Deneb, LightClientBootstrapDeneb),
        LightClientHeader::Electra(inner) => upgraded!(inner, Electra, LightClientBootstrapElectra),
        LightClientHeader::Fulu(inner) => upgraded!(inner, Fulu, LightClientBootstrapFulu),
    })
}

/// Locally upgrade an update, preserving its signing root, signature, committees and slots.
///
/// Electra normalizes both state branches by PREPENDING zeros; empty branches stay empty.
/// This is only a representation conversion. The result is untrusted until validated; it is
/// not a [`crate::ValidatedLightClientUpdate`]. The original network object is not modified.
pub fn upgrade_light_client_update<E: EthSpec>(
    update: &LightClientUpdate<E>,
    target_fork: ForkName,
) -> Result<LightClientUpdate<E>, LightClientSyncError> {
    let target_schema = LightClientStoreSchema::try_from(target_fork)?;
    let view = UpdateView::new(update);
    let attested = upgrade_light_client_header(&view.attested_header, target_fork)?;
    let finalized = upgrade_light_client_header(&view.finalized_header, target_fork)?;
    let (committee_depth, finality_depth) = if target_schema == LightClientStoreSchema::Electra {
        (
            NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA,
            FINALIZED_ROOT_PROOF_LEN_ELECTRA,
        )
    } else {
        (NEXT_SYNC_COMMITTEE_PROOF_LEN, FINALIZED_ROOT_PROOF_LEN)
    };
    let committee_branch = normalize_branch(view.next_committee_branch, committee_depth)?;
    let finality_branch = normalize_branch(view.finality_branch, finality_depth)?;
    let committee_branch_len = committee_branch.len();
    let finality_branch_len = finality_branch.len();
    macro_rules! upgraded {
        ($attested:ident, $finalized:ident, $variant:ident, $type:ident) => {
            LightClientUpdate::$variant($type {
                attested_header: $attested,
                finalized_header: $finalized,
                next_sync_committee: update.next_sync_committee().clone(),
                next_sync_committee_branch: committee_branch.try_into().map_err(|_| {
                    LightClientSyncError::InvalidUpgradeBranchLength {
                        actual: committee_branch_len,
                        expected: committee_depth,
                    }
                })?,
                finality_branch: finality_branch.try_into().map_err(|_| {
                    LightClientSyncError::InvalidUpgradeBranchLength {
                        actual: finality_branch_len,
                        expected: finality_depth,
                    }
                })?,
                sync_aggregate: update.sync_aggregate().clone(),
                signature_slot: *update.signature_slot(),
            })
        };
    }
    Ok(match (attested, finalized) {
        (LightClientHeader::Altair(a), LightClientHeader::Altair(f)) => {
            upgraded!(a, f, Altair, LightClientUpdateAltair)
        }
        (LightClientHeader::Capella(a), LightClientHeader::Capella(f)) => {
            upgraded!(a, f, Capella, LightClientUpdateCapella)
        }
        (LightClientHeader::Deneb(a), LightClientHeader::Deneb(f)) => {
            upgraded!(a, f, Deneb, LightClientUpdateDeneb)
        }
        (LightClientHeader::Electra(a), LightClientHeader::Electra(f)) => {
            upgraded!(a, f, Electra, LightClientUpdateElectra)
        }
        (LightClientHeader::Fulu(a), LightClientHeader::Fulu(f)) => {
            upgraded!(a, f, Fulu, LightClientUpdateFulu)
        }
        (_, finalized) => {
            return Err(LightClientSyncError::HeaderVariantMismatch {
                expected: target_fork,
                actual: header_variant(&finalized),
            });
        }
    })
}

fn normalize_branch(
    branch: &[Hash256],
    depth: usize,
) -> Result<Vec<Hash256>, LightClientSyncError> {
    let padding = depth.checked_sub(branch.len()).ok_or(
        LightClientSyncError::InvalidUpgradeBranchLength {
            actual: branch.len(),
            expected: depth,
        },
    )?;
    let mut normalized = vec![Hash256::default(); padding];
    normalized.extend_from_slice(branch);
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_by_prepending_zeros_without_changing_existing_nodes() {
        let branch = [Hash256::repeat_byte(1), Hash256::repeat_byte(2)];
        let upgraded = normalize_branch(&branch, 3).unwrap();
        assert_eq!(upgraded, vec![Hash256::default(), branch[0], branch[1]]);
        assert_eq!(normalize_branch(&upgraded, 3).unwrap(), upgraded);
        assert_eq!(
            normalize_branch(&[], 3).unwrap(),
            vec![Hash256::default(); 3]
        );
    }

    #[test]
    fn cannot_truncate_a_branch_when_target_depth_is_smaller() {
        assert_eq!(
            normalize_branch(&[Hash256::default(); 3], 2),
            Err(LightClientSyncError::InvalidUpgradeBranchLength {
                actual: 3,
                expected: 2
            })
        );
    }
}
