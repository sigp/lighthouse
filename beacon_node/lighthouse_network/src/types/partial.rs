use crate::PeerId;
use libp2p::gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError};
use ssz::{Decode, Encode};
use std::fmt::Debug;
use std::sync::Arc;
use types::EthSpec;
use types::data::partial_data_column_sidecar::{CellBitmap, DanglingPartialDataColumn};

#[derive(Debug, Clone, PartialEq)]
pub struct PartialDataColumnSidecarMessage<E: EthSpec> {
    pub partial_column: Arc<DanglingPartialDataColumn<E>>,
}

impl<E: EthSpec> PartialDataColumnSidecarMessage<E> {
    pub fn new(partial_column: Arc<DanglingPartialDataColumn<E>>) -> Self {
        PartialDataColumnSidecarMessage { partial_column }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CellBitmapMetadata<E: EthSpec> {
    bitmap: CellBitmap<E>,
    encoded: Vec<u8>,
}

impl<E: EthSpec> Metadata for CellBitmapMetadata<E> {
    fn as_slice(&self) -> &[u8] {
        &self.encoded
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialError> {
        let data =
            CellBitmap::<E>::from_ssz_bytes(data).map_err(|_| PartialError::InvalidFormat)?;
        if data.len() != self.bitmap.len() {
            return Err(PartialError::OutOfRange);
        }
        let new_bitmap = self.bitmap.union(&data);
        if self.bitmap == new_bitmap {
            return Ok(false);
        }
        self.bitmap = new_bitmap;
        self.encoded = self.bitmap.as_ssz_bytes();
        Ok(true)
    }
}

impl<E: EthSpec> From<CellBitmap<E>> for CellBitmapMetadata<E> {
    fn from(value: CellBitmap<E>) -> Self {
        Self {
            encoded: value.as_ssz_bytes(),
            bitmap: value,
        }
    }
}

impl<E: EthSpec> Partial for PartialDataColumnSidecarMessage<E> {
    fn group_id(&self) -> Vec<u8> {
        self.partial_column.block_root.as_slice().to_vec()
    }

    fn metadata(&self) -> Vec<u8> {
        self.partial_column
            .sidecar
            .cells_present_bitmap
            .as_ssz_bytes()
    }

    fn partial_action_from_metadata(
        &self,
        _peer_id: PeerId,
        metadata: Option<&[u8]>,
    ) -> Result<PartialAction, PartialError> {
        match metadata {
            None => Ok(PartialAction {
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
                        (
                            sidecar.as_ssz_bytes(),
                            Box::new(CellBitmapMetadata::<E>::from(
                                peer_has.union(&sidecar.cells_present_bitmap),
                            )) as Box<dyn Metadata + 'static>,
                        )
                    });

                Ok(PartialAction { need, send })
            }
        }
    }
}
