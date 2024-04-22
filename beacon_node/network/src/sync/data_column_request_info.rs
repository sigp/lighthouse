use std::{collections::VecDeque, sync::Arc};
use beacon_chain::block_verification_types::RpcBlock;
use types::{DataColumnSidecar, EthSpec, VariableList};

use super::range_sync::ByRangeRequestType;

#[derive(Debug)]
pub struct DataColumnsRequestInfo<E: EthSpec> {
    /// Sidecars we have received awaiting for their corresponding block.
    accumulated_sidecars: VecDeque<Arc<DataColumnSidecar<E>>>,
    /// Whether the individual RPC request for data columns is finished or not.
    is_sidecars_stream_terminated: bool,
}

impl<E: EthSpec> DataColumnsRequestInfo<E> {

    pub fn new(request_type: ByRangeRequestType) -> Self {
        Self {
            accumulated_sidecars: <_>::default(),
            is_sidecars_stream_terminated: <_>::default(),
        }
    }

    pub fn get_request_type(&self) -> ByRangeRequestType {
        ByRangeRequestType::DataColumns
    }

    pub fn add_sidecar_response(&mut self, sidecar_opt: Option<Arc<DataColumnSidecar<E>>>) {
        match sidecar_opt {
            Some(sidecar) => self.accumulated_sidecars.push_back(sidecar),
            None => self.is_sidecars_stream_terminated = true,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.is_sidecars_stream_terminated
    }

    pub fn into_responses(self, rpc_blocks: Vec<RpcBlock<E>>) -> Result<Vec<RpcBlock<E>>, String> {
        let DataColumnsRequestInfo {
            accumulated_sidecars,
            ..
        } = self;

        // TODO slots per epoch
        let mut responses = Vec::with_capacity(rpc_blocks.len());

        for rpc_block in rpc_blocks {
            let block = rpc_block.as_block();
            let mut data_column_iter = accumulated_sidecars.into_iter().peekable();
            let mut data_column_list = Vec::with_capacity(E::max_blobs_per_block());
            while {
                let pair_next_data_column = data_column_iter
                    .peek()
                    .map(|sidecar| sidecar.slot() == block.slot())
                    .unwrap_or(false);
                pair_next_data_column
            } {
                data_column_list.push(data_column_iter.next().ok_or("Missing next data data column".to_string())?);
            }
    
            let mut data_columns_buffer = vec![None; E::max_data_columns_per_block()];
            for data_column in data_column_list {
                let data_column_index = data_column.index as usize;
                let Some(data_column_opt) = data_columns_buffer.get_mut(data_column_index) else {
                    return Err("Invalid data column index".to_string());
                };
                if data_column_opt.is_some() {
                    return Err("Repeat data column index".to_string());
                } else {
                    *data_column_opt = Some(data_column);
                }
            }
            let data_columns = VariableList::from(data_columns_buffer.into_iter().flatten().collect::<Vec<_>>());
            responses.push(RpcBlock::new(None, block, None, Some(data_columns)).map_err(|e| format!("{e:?}"))?)
        
        }
        
       

        // if accumulated sidecars is not empty, throw an error.
        if data_column_iter.next().is_some() {
            return Err("Received sidecars that don't pair well".to_string());
        }

        Ok(responses)
    }
}