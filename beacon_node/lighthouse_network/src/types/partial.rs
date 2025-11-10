use gossipsub::partial::Metadata;
use gossipsub::{Partial, PartialMessageError};
use ssz::{Decode, Encode};
use std::cmp::Ordering;
use std::fmt::Debug;
use std::sync::Arc;
use types::EthSpec;
use types::partial_data_column_sidecar::{CellBitmap, DanglingPartialDataColumn};

#[derive(Debug, Clone, PartialEq)]
pub struct PartialDataColumnSidecarMessage<E: EthSpec> {
    pub partial_column: Arc<DanglingPartialDataColumn<E>>,
    metadata: CellBitmapMetadata<E>,
    send_eager: Option<SendEager<E>>,
}

impl<E: EthSpec> PartialDataColumnSidecarMessage<E> {
    pub fn new(partial_column: Arc<DanglingPartialDataColumn<E>>) -> Self {
        PartialDataColumnSidecarMessage {
            metadata: partial_column.sidecar.cells_present_bitmap.clone().into(),
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
pub struct CellBitmapMetadata<E: EthSpec> {
    bitmap: CellBitmap<E>,
}

impl<E: EthSpec> Metadata for CellBitmapMetadata<E> {
    fn decode(bytes: &[u8]) -> Result<Self, PartialMessageError>
    where
        Self: Sized,
    {
        Ok(CellBitmapMetadata {
            bitmap: CellBitmap::<E>::from_ssz_bytes(bytes)
                .map_err(|_| PartialMessageError::InvalidFormat)?,
        })
    }

    fn compare(&self, other: &Self) -> Option<Ordering> {
        let self_subset = self.bitmap.is_subset(&other.bitmap);
        let other_subset = other.bitmap.is_subset(&self.bitmap);
        match (self_subset, other_subset) {
            (true, true) => Some(Ordering::Equal),
            (true, false) => Some(Ordering::Less),
            (false, true) => Some(Ordering::Greater),
            (false, false) => None,
        }
    }

    fn encode(&self) -> Vec<u8> {
        self.bitmap.as_ssz_bytes()
    }

    fn update(&mut self, data: &Self) -> Result<bool, PartialMessageError> {
        let new_bitmap = self.bitmap.union(&data.bitmap);
        if self.bitmap == new_bitmap {
            return Ok(false);
        }
        self.bitmap = new_bitmap;
        Ok(true)
    }
}

impl<E: EthSpec> From<CellBitmap<E>> for CellBitmapMetadata<E> {
    fn from(bitmap: CellBitmap<E>) -> Self {
        Self { bitmap }
    }
}

impl<E: EthSpec> Partial for PartialDataColumnSidecarMessage<E> {
    type Metadata = CellBitmapMetadata<E>;

    fn group_id(&self) -> Vec<u8> {
        self.partial_column.block_root.to_vec()
    }

    fn metadata(&self) -> &Self::Metadata {
        &self.metadata
    }

    fn partial_message_bytes_from_metadata(
        &self,
        metadata: &Self::Metadata,
    ) -> Result<Option<Vec<u8>>, PartialMessageError> {
        Ok(self
            .partial_column
            .sidecar
            .with_missing_cells(&metadata.bitmap)
            .map(|message| message.as_ssz_bytes()))
    }

    fn data_for_eager_push(
        &self,
    ) -> Result<Option<(Vec<u8>, Self::Metadata)>, PartialMessageError> {
        Ok(self.send_eager.clone().map(|eager| (eager.data, eager.metadata)))
    }
}
