//! Shared helper for building partial-column gossip messages (#10104).
//!
//! Used by the gossip block path and the HTTP publish path.

use beacon_chain::fetch_blobs::PartialHeaderOrBid;
use beacon_chain::partial_data_column_assembler::AssemblyColumn;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::PubsubPartialMessage;
use logging::crit;
use ssz_types::{ProgressiveVariableList, VariableList};
use std::collections::HashSet;
use std::sync::Arc;
use types::{
    CellBitmap, ColumnIndex, EthSpec, Hash256, PartialDataColumn, PartialDataColumnFulu,
    PartialDataColumnGloas, PartialDataColumnSidecarFulu, PartialDataColumnSidecarGloas,
};

/// Build partial-column gossip messages for `block_root`.
///
/// Includes messages for any locally held partials plus empty placeholders for
/// missing custody columns. Returns an empty vec when partial columns are
/// disabled or there are no blob commitments.
pub fn build_partial_column_request_messages<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    header_or_bid: &PartialHeaderOrBid<T::EthSpec>,
    block_root: Hash256,
) -> Vec<PubsubPartialMessage<T::EthSpec>> {
    if header_or_bid.kzg_commitments().is_empty() {
        return vec![];
    }

    if !chain.config.enable_partial_columns {
        return vec![];
    }

    let epoch = header_or_bid.slot().epoch(T::EthSpec::slots_per_epoch());
    let custody_columns = chain.custody_context.sampling_columns_for_epoch(epoch);

    let mut present_indices: HashSet<ColumnIndex> = HashSet::new();
    let mut messages: Vec<PubsubPartialMessage<T::EthSpec>> = match header_or_bid {
        PartialHeaderOrBid::PartialHeader(header) => chain
            .data_availability_checker
            .partial_assembler()
            .map(|assembler| assembler.get_columns_and_mark_as_local_fetched(block_root, header))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|column| {
                let column = match column {
                    AssemblyColumn::Incomplete(partial) => partial.into_inner(),
                    AssemblyColumn::Complete(full) => {
                        match full.as_data_column().to_partial() {
                            Ok(PartialDataColumn::Fulu(fulu)) => Arc::new(fulu),
                            // The Fulu assembler never holds Gloas columns.
                            Ok(PartialDataColumn::Gloas(_)) => {
                                crit!("Found gloas column in Fulu partial assembler");
                                return None;
                            }
                            // Unreachable: DataColumn and CellBitmap share a bound.
                            Err(err) => {
                                crit!(?err, "Failed to convert full column to partial");
                                return None;
                            }
                        }
                    }
                };
                present_indices.insert(column.index);
                let mut request_cells = column.sidecar.cells_present_bitmap.clone_zeroed();
                request_cells.not_inplace();
                Some(PubsubPartialMessage::DataColumnFulu {
                    column,
                    request_cells,
                    header: header.clone(),
                })
            })
            .collect(),
        PartialHeaderOrBid::Bid(bid) => chain
            .pending_payload_cache
            .get_partials_and_mark_as_local_fetched(block_root, bid)
            .into_iter()
            .map(|partial| {
                present_indices.insert(partial.index());
                let column = partial.into_inner();
                let mut request_cells = column.sidecar.cells_present_bitmap.clone_zeroed();
                request_cells.not_inplace();
                PubsubPartialMessage::DataColumnGloas {
                    column,
                    request_cells,
                }
            })
            .collect(),
    };

    // For each custody column without any local partial, send an empty placeholder
    // that requests all cells.
    let num_cells = header_or_bid.kzg_commitments().len();
    for col_idx in custody_columns {
        if present_indices.contains(col_idx) {
            continue;
        }
        // `kzg_commitments.len()` is bounded by `MaxBlobCommitmentsPerBlock`, so the
        // bitmap constructor is infallible.
        let Ok(cells_present_bitmap) = CellBitmap::<T::EthSpec>::with_capacity(num_cells) else {
            crit!(
                %block_root,
                num_cells,
                column_index = %col_idx,
                "CellBitmap construction failed despite being bounded by MaxBlobCommitmentsPerBlock"
            );
            continue;
        };
        let request_cells = cells_present_bitmap.not();
        let message = match header_or_bid {
            PartialHeaderOrBid::PartialHeader(header) => PubsubPartialMessage::DataColumnFulu {
                column: Arc::new(PartialDataColumnFulu {
                    block_root,
                    index: *col_idx,
                    sidecar: PartialDataColumnSidecarFulu {
                        cells_present_bitmap,
                        column: VariableList::empty(),
                        kzg_proofs: VariableList::empty(),
                        header: None.into(),
                    },
                }),
                request_cells,
                header: header.clone(),
            },
            PartialHeaderOrBid::Bid(_) => PubsubPartialMessage::DataColumnGloas {
                column: Arc::new(PartialDataColumnGloas {
                    block_root,
                    slot: header_or_bid.slot(),
                    index: *col_idx,
                    sidecar: PartialDataColumnSidecarGloas {
                        cells_present_bitmap,
                        column: ProgressiveVariableList::empty(),
                        kzg_proofs: ProgressiveVariableList::empty(),
                    },
                }),
                request_cells,
            },
        };
        messages.push(message);
    }

    messages
}
