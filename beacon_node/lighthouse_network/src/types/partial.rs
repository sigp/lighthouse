use gossipsub::partial::{Metadata, PublishAction};
use gossipsub::{Partial, PartialMessageError};
use ssz::{Decode, Encode};
use std::fmt::Debug;
use std::sync::Arc;
use types::EthSpec;
use types::partial_data_column_sidecar::{CellBitmap, DanglingPartialDataColumn};

#[derive(Debug, Clone, PartialEq)]
pub struct PartialDataColumnSidecarMessage<E: EthSpec> {
    pub partial_column: Arc<DanglingPartialDataColumn<E>>,
    send_eager: Option<SendEager<E>>,
}

impl<E: EthSpec> PartialDataColumnSidecarMessage<E> {
    pub fn new(partial_column: Arc<DanglingPartialDataColumn<E>>) -> Self {
        PartialDataColumnSidecarMessage {
            partial_column,
            send_eager: None,
        }
    }

    pub fn eagerly_send(&mut self, cells: &CellBitmap<E>) {
        let Some(eager) = self
            .partial_column
            .sidecar
            .clone_filter(|idx| cells.get(idx).unwrap_or(false))
        else {
            return;
        };

        self.send_eager = Some(SendEager {
            data: eager.as_ssz_bytes(),
            metadata: eager.cells_present_bitmap.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SendEager<E: EthSpec> {
    /// The encoded message to send eagerly, i.e. when we have no metadata for that peer.
    data: Vec<u8>,
    /// The metadata to associate with a peer after sending it the eager message.
    metadata: CellBitmapMetadata<E>,
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

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialMessageError> {
        let data = CellBitmap::<E>::from_ssz_bytes(data)
            .map_err(|_| PartialMessageError::InvalidFormat)?;
        if data.len() != self.bitmap.len() {
            return Err(PartialMessageError::OutOfRange);
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
    fn group_id(&self) -> impl AsRef<[u8]> {
        &self.partial_column.block_root
    }

    fn parts_metadata(&self) -> impl AsRef<[u8]> {
        self.partial_column
            .sidecar
            .cells_present_bitmap
            .as_ssz_bytes()
    }

    fn partial_message_bytes_from_metadata(
        &self,
        metadata: Option<impl AsRef<[u8]>>,
    ) -> Result<PublishAction, PartialMessageError> {
        match metadata {
            None => {
                // Send the eager message if any
                match &self.send_eager {
                    None => Ok(PublishAction::NothingToSend),
                    Some(send) => Ok(PublishAction::Send {
                        message: send.data.clone(),
                        metadata: Box::new(send.metadata.clone()),
                    }),
                }
            }
            Some(metadata) => {
                let peer_has = CellBitmap::<E>::from_ssz_bytes(metadata.as_ref())
                    .map_err(|_| PartialMessageError::InvalidFormat)?;
                if peer_has == self.partial_column.sidecar.cells_present_bitmap {
                    return Ok(PublishAction::SameMetadata);
                }

                let Some(send) = self.partial_column.sidecar.with_missing_cells(&peer_has) else {
                    return Ok(PublishAction::NothingToSend);
                };

                let new_metadata = peer_has.union(&send.cells_present_bitmap);
                Ok(PublishAction::Send {
                    message: send.as_ssz_bytes().to_vec(),
                    metadata: Box::new(CellBitmapMetadata::<E>::from(new_metadata)),
                })
            }
        }
    }
}
