use crate::PeerId;
use libp2p::gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError};
use parking_lot::Mutex;
use ssz::{Decode, Encode};
use ssz_types::VariableList;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::debug;
use types::data::partial_data_column_sidecar::{CellBitmap, PartialDataColumn};
use types::partial_data_column_sidecar::PartialDataColumnSidecar;
use types::{EthSpec, Hash256};

pub type HeaderSentSet = Arc<Mutex<HashSet<PeerId>>>;

pub struct NoHeaderInColumnError;

#[derive(Debug, Clone)]
pub struct OutgoingPartialColumn<E: EthSpec> {
    pub partial_column: Arc<PartialDataColumn<E>>,
    pub header_message: Vec<u8>,
    pub header_sent_set: HeaderSentSet,
}

impl<E: EthSpec> OutgoingPartialColumn<E> {
    pub fn new(
        partial_column: Arc<PartialDataColumn<E>>,
        header_sent_set: HeaderSentSet,
    ) -> Result<Self, NoHeaderInColumnError> {
        let Some(header) = partial_column.sidecar.header.first().cloned() else {
            return Err(NoHeaderInColumnError);
        };

        let header_message = PartialDataColumnSidecar {
            cells_present_bitmap: CellBitmap::<E>::with_capacity(
                partial_column.sidecar.cells_present_bitmap.len(),
            )
            .expect("Taking length from bitmap with same bound"),
            column: VariableList::empty(),
            kzg_proofs: VariableList::empty(),
            header: VariableList::repeat_full(header),
        }
        .as_ssz_bytes();

        Ok(OutgoingPartialColumn {
            partial_column,
            header_message,
            header_sent_set,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CellBitmapMetadata<E: EthSpec> {
    Unknown,
    Known {
        bitmap: CellBitmap<E>,
        encoded: Vec<u8>,
    },
}

impl<E: EthSpec> Metadata for CellBitmapMetadata<E> {
    fn as_slice(&self) -> &[u8] {
        match self {
            CellBitmapMetadata::Unknown => &[],
            CellBitmapMetadata::Known { encoded, .. } => encoded,
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialError> {
        let peer_bitmap =
            CellBitmap::<E>::from_ssz_bytes(data).map_err(|_| PartialError::InvalidFormat)?;

        let CellBitmapMetadata::Known { bitmap, encoded } = self else {
            *self = CellBitmapMetadata::Known {
                bitmap: peer_bitmap,
                encoded: data.to_vec(),
            };
            return Ok(true);
        };

        if peer_bitmap.len() != bitmap.len() {
            return Err(PartialError::OutOfRange);
        }
        let new_bitmap = bitmap.union(&peer_bitmap);
        if *bitmap == new_bitmap {
            return Ok(false);
        }
        *bitmap = new_bitmap;
        *encoded = bitmap.as_ssz_bytes();
        Ok(true)
    }
}

impl<E: EthSpec> From<CellBitmap<E>> for CellBitmapMetadata<E> {
    fn from(value: CellBitmap<E>) -> Self {
        Self::Known {
            encoded: value.as_ssz_bytes(),
            bitmap: value,
        }
    }
}

impl<E: EthSpec> Partial for OutgoingPartialColumn<E> {
    fn group_id(&self) -> Vec<u8> {
        let mut group_id = Vec::with_capacity(Hash256::len_bytes() + 1);
        group_id.push(0);
        group_id.extend_from_slice(self.partial_column.block_root.as_slice());
        group_id
    }

    fn metadata(&self) -> Vec<u8> {
        self.partial_column
            .sidecar
            .cells_present_bitmap
            .as_ssz_bytes()
    }

    fn partial_action_from_metadata(
        &self,
        peer_id: PeerId,
        metadata: Option<&[u8]>,
    ) -> Result<PartialAction, PartialError> {
        match metadata {
            None => {
                // send the header-only messsage to the peer if we have not yet
                let send = self.header_sent_set.lock().insert(peer_id).then(|| {
                    (
                        self.header_message.clone(),
                        Box::new(CellBitmapMetadata::<E>::Unknown) as Box<dyn Metadata>,
                    )
                });
                debug!(
                    peer=%peer_id,
                    group_id=%self.partial_column.block_root,
                    column_index=self.partial_column.index,
                    sending_header=send.is_some(),
                    "Partial send: No metadata"
                );

                Ok(PartialAction { need: false, send })
            }
            Some([]) => Ok(PartialAction {
                need: false,
                send: None,
            }),
            Some(metadata) => {
                let peer_has = CellBitmap::<E>::from_ssz_bytes(metadata)
                    .map_err(|_| PartialError::InvalidFormat)?;
                let need = !peer_has.is_subset(&self.partial_column.sidecar.cells_present_bitmap);

                let send = self
                    .partial_column
                    .sidecar
                    .with_missing_cells(&peer_has)
                    .map(|sidecar| {
                        debug!(
                            peer=%peer_id,
                            group_id=%self.partial_column.block_root,
                            column_index=self.partial_column.index,
                            metadata=%peer_has,
                            sending=%sidecar.cells_present_bitmap,
                            "Partial send: Sending"
                        );
                        (
                            sidecar.as_ssz_bytes(),
                            Box::new(CellBitmapMetadata::<E>::from(
                                peer_has.union(&sidecar.cells_present_bitmap),
                            )) as Box<dyn Metadata + 'static>,
                        )
                    });

                if send.is_none() {
                    debug!(
                        peer=%peer_id,
                        group_id=%self.partial_column.block_root,
                        column_index=self.partial_column.index,
                        metadata=%peer_has,
                        "Partial send: Nothing to send"
                    );
                }

                Ok(PartialAction { need, send })
            }
        }
    }
}
