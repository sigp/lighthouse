use crate::PeerId;
use itertools::Itertools;
use libp2p::gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError};
use parking_lot::Mutex;
use ssz::{Decode, Encode};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::debug;
use types::{
    CellBitmap, EthSpec, Hash256, PartialDataColumn, PartialDataColumnHeader,
    PartialDataColumnPartsMetadata, PartialDataColumnSidecar, PartialDataColumnSidecarRef,
};

const PARTIAL_COLUMNS_VERSION_BYTE: u8 = 0;

pub type HeaderSentSet = Arc<Mutex<HashSet<PeerId>>>;

#[derive(Debug, Clone)]
pub struct OutgoingPartialColumn<E: EthSpec> {
    partial_column: Arc<PartialDataColumn<E>>,
    metadata: MaybeKnownMetadata<E>,
    header_message: Vec<u8>,
    header_sent_set: HeaderSentSet,
}

impl<E: EthSpec> OutgoingPartialColumn<E> {
    pub fn new(
        partial_column: Arc<PartialDataColumn<E>>,
        header: &PartialDataColumnHeader<E>,
        header_sent_set: HeaderSentSet,
    ) -> Self {
        // For now, always request all cells
        let mut request = partial_column.sidecar.cells_present_bitmap.clone();
        for idx in 0..request.len() {
            request
                .set(idx, true)
                .expect("Bound asserted via `len` above");
        }
        let metadata = PartialDataColumnPartsMetadata::<E> {
            available: partial_column.sidecar.cells_present_bitmap.clone(),
            request: partial_column.sidecar.cells_present_bitmap.clone(),
        }
        .into();

        let header_message = PartialDataColumnSidecarRef {
            cells_present_bitmap: CellBitmap::<E>::with_capacity(
                partial_column.sidecar.cells_present_bitmap.len(),
            )
            .expect("Taking length from bitmap with same bound"),
            column: vec![],
            kzg_proofs: vec![],
            header: vec![header],
        }
        .as_ssz_bytes();

        OutgoingPartialColumn {
            partial_column,
            metadata,
            header_message,
            header_sent_set,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MaybeKnownMetadata<E: EthSpec> {
    Unknown,
    Known {
        metadata: Box<PartialDataColumnPartsMetadata<E>>,
        encoded: Vec<u8>,
    },
}

impl<E: EthSpec> MaybeKnownMetadata<E> {
    fn do_update(
        &mut self,
        received: PartialDataColumnPartsMetadata<E>,
    ) -> Result<bool, PartialError> {
        let MaybeKnownMetadata::Known { metadata, encoded } = self else {
            *self = MaybeKnownMetadata::Known {
                encoded: received.as_ssz_bytes(),
                metadata: Box::new(received),
            };
            return Ok(true);
        };

        if ![
            received.available.len(),
            received.request.len(),
            metadata.available.len(),
            metadata.request.len(),
        ]
        .into_iter()
        .all_equal()
        {
            return Err(PartialError::OutOfRange);
        }
        let new_available = metadata.available.union(&received.available);
        let new_request = metadata.request.union(&received.request);
        if metadata.available == new_available && metadata.request == new_request {
            return Ok(false);
        }
        metadata.available = new_available;
        metadata.request = new_request;
        *encoded = metadata.as_ssz_bytes();
        Ok(true)
    }
}

impl<E: EthSpec> Metadata for MaybeKnownMetadata<E> {
    fn as_slice(&self) -> &[u8] {
        match self {
            MaybeKnownMetadata::Unknown => &[],
            MaybeKnownMetadata::Known { encoded, .. } => encoded,
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, PartialError> {
        let received = PartialDataColumnPartsMetadata::from_ssz_bytes(data)
            .map_err(|_| PartialError::InvalidFormat)?;

        self.do_update(received)
    }

    fn update_from_data(&mut self, data: &[u8]) -> Result<(), PartialError> {
        if data.is_empty() {
            return Ok(());
        }

        let sidecar = PartialDataColumnSidecar::<E>::from_ssz_bytes(data)
            .map_err(|_| PartialError::InvalidFormat)?;

        self.do_update(PartialDataColumnPartsMetadata {
            available: sidecar.cells_present_bitmap.clone(),
            request: sidecar.cells_present_bitmap,
        })
        .map(|_| ())
    }
}

impl<E: EthSpec> From<PartialDataColumnPartsMetadata<E>> for MaybeKnownMetadata<E> {
    fn from(metadata: PartialDataColumnPartsMetadata<E>) -> Self {
        Self::Known {
            encoded: metadata.as_ssz_bytes(),
            metadata: Box::new(metadata),
        }
    }
}

impl<E: EthSpec> Partial for OutgoingPartialColumn<E> {
    fn group_id(&self) -> Vec<u8> {
        let mut group_id = Vec::with_capacity(Hash256::len_bytes() + 1);
        group_id.push(PARTIAL_COLUMNS_VERSION_BYTE);
        group_id.extend_from_slice(self.partial_column.block_root.as_slice());
        group_id
    }

    fn metadata(&self) -> Box<dyn Metadata> {
        Box::new(self.metadata.clone())
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
                        Box::new(MaybeKnownMetadata::<E>::Unknown) as Box<dyn Metadata>,
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
                let peer_metadata = PartialDataColumnPartsMetadata::<E>::from_ssz_bytes(metadata)
                    .map_err(|_| PartialError::InvalidFormat)?;
                let expected_len = self.partial_column.sidecar.cells_present_bitmap.len();
                if peer_metadata.available.len() != expected_len
                    || peer_metadata.request.len() != expected_len
                {
                    return Err(PartialError::InvalidFormat);
                }

                let need = !peer_metadata
                    .available
                    .is_subset(&self.partial_column.sidecar.cells_present_bitmap);
                let want = peer_metadata.request.difference(&peer_metadata.available);

                let send = self
                    .partial_column
                    .sidecar
                    .filter(|idx| want.get(idx).expect("Bound checked above"))
                    .map(|sidecar| {
                        debug!(
                            peer=%peer_id,
                            group_id=%self.partial_column.block_root,
                            column_index=self.partial_column.index,
                            metadata=%peer_metadata,
                            sending=%sidecar.cells_present_bitmap,
                            "Partial send: Sending"
                        );
                        (
                            sidecar.as_ssz_bytes(),
                            Box::new(MaybeKnownMetadata::<E>::from(
                                PartialDataColumnPartsMetadata {
                                    available: peer_metadata
                                        .available
                                        .union(&sidecar.cells_present_bitmap),
                                    request: peer_metadata
                                        .request
                                        .union(&sidecar.cells_present_bitmap),
                                },
                            )) as Box<dyn Metadata + 'static>,
                        )
                    });

                if send.is_none() {
                    debug!(
                        peer=%peer_id,
                        group_id=%self.partial_column.block_root,
                        column_index=self.partial_column.index,
                        metadata=%peer_metadata,
                        "Partial send: Nothing to send"
                    );
                }

                Ok(PartialAction { need, send })
            }
        }
    }
}
