use beacon_chain::block_verification_types::RpcBlock;
use ssz_types::VariableList;
use std::{collections::VecDeque, sync::Arc};
use types::{BlobSidecar, DataColumnSidecar, EthSpec, SignedBeaconBlock};

#[derive(Debug, Default)]
pub struct BlocksAndDataColumnsRequestInfo<T: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    accumulated_blocks: VecDeque<Arc<SignedBeaconBlock<T>>>,
    /// Column sidecars we have received awaiting for their corresponding block.
    accumulated_data_column_sidecars: VecDeque<Arc<DataColumnSidecar<T>>>,
    /// Whether the individual RPC request for blocks is finished or not.
    is_blocks_stream_terminated: bool,
    /// Whether the individual RPC request for data column sidecars is finished or not.
    is_data_column_sidecars_stream_terminated: bool,
}

impl<E: EthSpec> BlocksAndDataColumnsRequestInfo<E> {
    pub fn add_block_response(&mut self, block_opt: Option<Arc<SignedBeaconBlock<E>>>) {
        match block_opt {
            Some(block) => self.accumulated_blocks.push_back(block),
            None => self.is_blocks_stream_terminated = true,
        }
    }

    pub fn add_data_column_sidecar_response(
        &mut self,
        data_column_sidecar_opt: Option<Arc<DataColumnSidecar<E>>>,
    ) {
        match data_column_sidecar_opt {
            Some(data_column_sidecar) => self
                .accumulated_data_column_sidecars
                .push_back(data_column_sidecar),
            None => self.is_data_column_sidecars_stream_terminated = true,
        }
    }

    pub fn into_responses(self) -> Result<Vec<RpcBlock<E>>, String> {
        let BlocksAndDataColumnsRequestInfo {
            accumulated_blocks,
            accumulated_data_column_sidecars,
            ..
        } = self;

        // There can't be more more data columns than blocks. i.e. sending any column (empty
        // included) for a skipped slot is not permitted.
        let mut responses = Vec::with_capacity(accumulated_blocks.len());
        let mut data_column_iter = accumulated_data_column_sidecars.into_iter().peekable();
        for block in accumulated_blocks.into_iter() {
            let mut data_column_list = Vec::with_capacity(E::number_of_columns());
            while {
                let pair_next_data_column = data_column_iter
                    .peek()
                    .map(|data_column_sidecar| data_column_sidecar.slot() == block.slot())
                    .unwrap_or(false);
                pair_next_data_column
            } {
                data_column_list.push(
                    data_column_iter
                        .next()
                        .ok_or("Missing next data column".to_string())?,
                );
            }

            let mut data_column_buffer = vec![None; E::number_of_columns()];
            for data_column in data_column_list {
                let data_column_index = data_column.index as usize;
                let Some(data_column_opt) = data_column_buffer.get_mut(data_column_index) else {
                    return Err("Invalid data column index".to_string());
                };
                if data_column_opt.is_some() {
                    return Err("Repeat data column index".to_string());
                } else {
                    *data_column_opt = Some(data_column);
                }
            }
            let data_columns =
                VariableList::from(data_column_buffer.into_iter().flatten().collect::<Vec<_>>());
            responses.push(
                RpcBlock::new(None, block, None, Some(data_columns))
                    .map_err(|e| format!("{e:?}"))?,
            )
        }

        // if accumulated sidecars is not empty, throw an error.
        if data_column_iter.next().is_some() {
            return Err("Received sidecars that don't pair well".to_string());
        }

        Ok(responses)
    }

    pub fn is_finished(&self) -> bool {
        self.is_blocks_stream_terminated && self.is_data_column_sidecars_stream_terminated
    }
}

#[derive(Debug, Default)]
pub struct BlocksAndBlobsRequestInfo<T: EthSpec> {
    /// Blocks we have received awaiting for their corresponding sidecar.
    accumulated_blocks: VecDeque<Arc<SignedBeaconBlock<T>>>,
    /// Sidecars we have received awaiting for their corresponding block.
    accumulated_sidecars: VecDeque<Arc<BlobSidecar<T>>>,
    /// Whether the individual RPC request for blocks is finished or not.
    is_blocks_stream_terminated: bool,
    /// Whether the individual RPC request for sidecars is finished or not.
    is_sidecars_stream_terminated: bool,
}

impl<T: EthSpec> BlocksAndBlobsRequestInfo<T> {
    pub fn add_block_response(&mut self, block_opt: Option<Arc<SignedBeaconBlock<T>>>) {
        match block_opt {
            Some(block) => self.accumulated_blocks.push_back(block),
            None => self.is_blocks_stream_terminated = true,
        }
    }

    pub fn add_sidecar_response(&mut self, sidecar_opt: Option<Arc<BlobSidecar<T>>>) {
        match sidecar_opt {
            Some(sidecar) => self.accumulated_sidecars.push_back(sidecar),
            None => self.is_sidecars_stream_terminated = true,
        }
    }

    pub fn into_responses(self) -> Result<Vec<RpcBlock<T>>, String> {
        let BlocksAndBlobsRequestInfo {
            accumulated_blocks,
            accumulated_sidecars,
            ..
        } = self;

        // There can't be more more blobs than blocks. i.e. sending any blob (empty
        // included) for a skipped slot is not permitted.
        let mut responses = Vec::with_capacity(accumulated_blocks.len());
        let mut blob_iter = accumulated_sidecars.into_iter().peekable();
        for block in accumulated_blocks.into_iter() {
            let mut blob_list = Vec::with_capacity(T::max_blobs_per_block());
            while {
                let pair_next_blob = blob_iter
                    .peek()
                    .map(|sidecar| sidecar.slot() == block.slot())
                    .unwrap_or(false);
                pair_next_blob
            } {
                blob_list.push(blob_iter.next().ok_or("Missing next blob".to_string())?);
            }

            let mut blobs_buffer = vec![None; T::max_blobs_per_block()];
            for blob in blob_list {
                let blob_index = blob.index as usize;
                let Some(blob_opt) = blobs_buffer.get_mut(blob_index) else {
                    return Err("Invalid blob index".to_string());
                };
                if blob_opt.is_some() {
                    return Err("Repeat blob index".to_string());
                } else {
                    *blob_opt = Some(blob);
                }
            }
            let blobs = VariableList::from(blobs_buffer.into_iter().flatten().collect::<Vec<_>>());
            responses
                .push(RpcBlock::new(None, block, Some(blobs), None).map_err(|e| format!("{e:?}"))?)
        }

        // if accumulated sidecars is not empty, throw an error.
        if blob_iter.next().is_some() {
            return Err("Received sidecars that don't pair well".to_string());
        }

        Ok(responses)
    }

    pub fn is_finished(&self) -> bool {
        self.is_blocks_stream_terminated && self.is_sidecars_stream_terminated
    }
}
