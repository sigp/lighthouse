use crate::PeerId;
use itertools::Itertools;
use libp2p::gossipsub::partial_messages::{Metadata, Partial, PartialAction, PartialError};
use parking_lot::Mutex;
use ssz::{Decode, Encode};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use tracing::{error, trace};
use types::core::{EthSpec, Hash256};
use types::data::{
    CellBitmap, PartialDataColumn, PartialDataColumnHeader, PartialDataColumnPartsMetadata,
    PartialDataColumnSidecar, PartialDataColumnSidecarRef,
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
        requests: CellBitmap<E>,
    ) -> Self {
        // Always set the request bit for available cells.
        //
        // Gossipsub applys certain optimisations to avoid sending redundant messages. This
        // requires that we stay consistent with our metadata. Gossipsub uses the `Metadata` trait
        // impl below to determine whether it can perform these optimisations.
        //
        // If we request a cell and then receive it, un-setting the request bit in the next
        // published message may cause issues:
        // Gossipsub tries to avoid the impact of application race conditions by checking newly
        // published metadata against previously published metadata. This no longer functions
        // correctly if request bits are unset between calls, as Gossipsub will consider a message
        // with new requests as new info to be propagated, possibly overwriting previous messages
        // with more cells (but fewer request bits). This is because gossipsub will see that both
        // metadata have some bits that are not set in the other metadata and therefore cannot
        // decide which actually carries more data. By always setting request bits for available
        // cells, we avoid this issue, as requests will never be unset between calls.
        //
        // In other words, gossipsub relies on the fact that metadata is additive. The request bit
        // is, therefore, to be seen as a "request if not available" bit.
        let requests = requests.union(&partial_column.sidecar.cells_present_bitmap);

        let metadata = PartialDataColumnPartsMetadata::<E> {
            available: partial_column.sidecar.cells_present_bitmap.clone(),
            requests,
        }
        .into();

        let header_message = PartialDataColumnSidecarRef {
            cells_present_bitmap: partial_column.sidecar.cells_present_bitmap.clone_zeroed(),
            column: vec![],
            kzg_proofs: vec![],
            header: Some(header).into(),
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
            received.requests.len(),
            metadata.available.len(),
            metadata.requests.len(),
        ]
        .into_iter()
        .all_equal()
        {
            return Err(PartialError::OutOfRange);
        }
        let new_available = metadata.available.union(&received.available);
        let new_request = metadata.requests.union(&received.requests);
        if metadata.available == new_available && metadata.requests == new_request {
            return Ok(false);
        }
        metadata.available = new_available;
        metadata.requests = new_request;
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
            requests: sidecar.cells_present_bitmap,
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
                trace!(
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
                // The peer is apparently aware of the header, make sure we track that:
                self.header_sent_set.lock().insert(peer_id);

                let peer_metadata = PartialDataColumnPartsMetadata::<E>::from_ssz_bytes(metadata)
                    .map_err(|_| PartialError::InvalidFormat)?;
                let expected_len = self.partial_column.sidecar.cells_present_bitmap.len();
                if peer_metadata.available.len() != expected_len
                    || peer_metadata.requests.len() != expected_len
                {
                    return Err(PartialError::InvalidFormat);
                }

                let need = !peer_metadata
                    .available
                    .is_subset(&self.partial_column.sidecar.cells_present_bitmap);
                let want = peer_metadata.requests.difference(&peer_metadata.available);

                let send = self
                    .partial_column
                    .sidecar
                    .filter(|idx| want.get(idx).unwrap_or(false))
                    .map_err(|err| {
                        error!(?err, "Unexpected error filtering sidecar");
                        PartialError::InvalidFormat
                    })?
                    .map(|sidecar| {
                        trace!(
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
                                    requests: peer_metadata
                                        .requests
                                        .union(&sidecar.cells_present_bitmap),
                                },
                            )) as Box<dyn Metadata + 'static>,
                        )
                    });

                if send.is_none() {
                    trace!(
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

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Signature;
    use fixed_bytes::FixedBytesExtended;
    use libp2p::identity::Keypair;
    use ssz_types::FixedVector;
    use types::CellBitmap;
    use types::block::{BeaconBlockHeader, SignedBeaconBlockHeader};
    use types::core::{MinimalEthSpec, Slot};
    use types::data::PartialDataColumnHeader;

    type E = MinimalEthSpec;

    fn make_cell(marker: u8) -> types::Cell<E> {
        let mut cell = types::Cell::<E>::default();
        cell[0] = marker;
        cell
    }

    fn make_header(num_commitments: usize) -> PartialDataColumnHeader<E> {
        PartialDataColumnHeader {
            kzg_commitments: vec![types::KzgCommitment([0u8; 48]); num_commitments]
                .try_into()
                .unwrap(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot: Slot::new(1),
                    proposer_index: 0,
                    parent_root: Hash256::zero(),
                    state_root: Hash256::zero(),
                    body_root: Hash256::zero(),
                },
                signature: Signature::empty(),
            },
            kzg_commitments_inclusion_proof: FixedVector::new(
                vec![Hash256::zero(); E::kzg_commitments_inclusion_proof_depth()],
            )
            .unwrap(),
        }
    }

    fn make_partial_column(
        block_root: Hash256,
        total_blobs: usize,
        present_indices: &[usize],
    ) -> Arc<PartialDataColumn<E>> {
        let mut bitmap = CellBitmap::<E>::with_capacity(total_blobs).unwrap();
        for &idx in present_indices {
            bitmap.set(idx, true).unwrap();
        }

        Arc::new(PartialDataColumn {
            block_root,
            index: 0,
            sidecar: PartialDataColumnSidecar {
                cells_present_bitmap: bitmap,
                column: present_indices
                    .iter()
                    .map(|&idx| make_cell(idx as u8))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                kzg_proofs: present_indices
                    .iter()
                    .map(|_| types::KzgProof::empty())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                header: None.into(),
            },
        })
    }

    fn make_all_one_bitmap(len: usize) -> CellBitmap<E> {
        let mut request_cells = CellBitmap::<E>::with_capacity(len).unwrap();
        for idx in 0..request_cells.len() {
            request_cells.set(idx, true).unwrap();
        }
        request_cells
    }

    fn random_peer_id() -> PeerId {
        let keypair = Keypair::generate_ed25519();
        PeerId::from(keypair.public())
    }

    // -- MaybeKnownMetadata tests --

    #[test]
    fn update_from_unknown_initializes() {
        let mut meta = MaybeKnownMetadata::<E>::Unknown;
        let mut bitmap = CellBitmap::<E>::with_capacity(4).unwrap();
        bitmap.set(0, true).unwrap();
        let received = PartialDataColumnPartsMetadata {
            available: bitmap.clone(),
            requests: bitmap,
        };
        let changed = meta.do_update(received).unwrap();
        assert!(changed);
        assert!(matches!(meta, MaybeKnownMetadata::Known { .. }));
    }

    #[test]
    fn update_unions_bitmaps() {
        let mut bitmap1 = CellBitmap::<E>::with_capacity(4).unwrap();
        bitmap1.set(0, true).unwrap();
        let mut meta: MaybeKnownMetadata<E> = PartialDataColumnPartsMetadata {
            available: bitmap1.clone(),
            requests: bitmap1,
        }
        .into();

        let mut bitmap2 = CellBitmap::<E>::with_capacity(4).unwrap();
        bitmap2.set(1, true).unwrap();
        let changed = meta
            .do_update(PartialDataColumnPartsMetadata {
                available: bitmap2.clone(),
                requests: bitmap2,
            })
            .unwrap();
        assert!(changed);

        if let MaybeKnownMetadata::Known { metadata, .. } = &meta {
            assert!(metadata.available.get(0).unwrap());
            assert!(metadata.available.get(1).unwrap());
            assert!(!metadata.available.get(2).unwrap());
        } else {
            panic!("Expected Known metadata");
        }
    }

    #[test]
    fn update_returns_false_when_no_change() {
        let mut bitmap = CellBitmap::<E>::with_capacity(4).unwrap();
        bitmap.set(0, true).unwrap();
        bitmap.set(1, true).unwrap();
        let mut meta: MaybeKnownMetadata<E> = PartialDataColumnPartsMetadata {
            available: bitmap.clone(),
            requests: bitmap.clone(),
        }
        .into();

        // Update with a subset
        let mut subset = CellBitmap::<E>::with_capacity(4).unwrap();
        subset.set(0, true).unwrap();
        let changed = meta
            .do_update(PartialDataColumnPartsMetadata {
                available: subset.clone(),
                requests: subset,
            })
            .unwrap();
        assert!(!changed);
    }

    #[test]
    fn update_rejects_mismatched_lengths() {
        let mut bitmap4 = CellBitmap::<E>::with_capacity(4).unwrap();
        bitmap4.set(0, true).unwrap();
        let mut meta: MaybeKnownMetadata<E> = PartialDataColumnPartsMetadata {
            available: bitmap4.clone(),
            requests: bitmap4,
        }
        .into();

        let mut bitmap6 = CellBitmap::<E>::with_capacity(6).unwrap();
        bitmap6.set(0, true).unwrap();
        let result = meta.do_update(PartialDataColumnPartsMetadata {
            available: bitmap6.clone(),
            requests: bitmap6,
        });
        assert!(result.is_err());
    }

    // -- OutgoingPartialColumn::partial_action_from_metadata tests --

    #[test]
    fn no_metadata_sends_header_once() {
        let root = Hash256::repeat_byte(1);
        let header = make_header(4);
        let partial = make_partial_column(root, 4, &[0, 1]);
        let header_sent_set: HeaderSentSet = Arc::new(Mutex::new(HashSet::new()));
        let requests = make_all_one_bitmap(4);
        let outgoing = OutgoingPartialColumn::new(partial, &header, header_sent_set, requests);

        let peer = random_peer_id();

        // First call with no metadata → sends header
        let action = outgoing.partial_action_from_metadata(peer, None).unwrap();
        assert!(action.send.is_some());

        // Second call for same peer → no send
        let action2 = outgoing.partial_action_from_metadata(peer, None).unwrap();
        assert!(action2.send.is_none());
    }

    #[test]
    fn metadata_filters_cells_to_send() {
        let root = Hash256::repeat_byte(1);
        let header = make_header(4);
        // We have cells [0, 2, 3]
        let partial = make_partial_column(root, 4, &[0, 2, 3]);
        let header_sent_set: HeaderSentSet = Arc::new(Mutex::new(HashSet::new()));
        let requests = make_all_one_bitmap(4);
        let outgoing = OutgoingPartialColumn::new(partial, &header, header_sent_set, requests);

        let peer = random_peer_id();

        // Peer has [0, 1], wants [0, 1, 2, 3]
        let mut peer_available = CellBitmap::<E>::with_capacity(4).unwrap();
        peer_available.set(0, true).unwrap();
        peer_available.set(1, true).unwrap();
        let mut peer_request = CellBitmap::<E>::with_capacity(4).unwrap();
        for i in 0..4 {
            peer_request.set(i, true).unwrap();
        }
        let peer_meta = PartialDataColumnPartsMetadata::<E> {
            available: peer_available,
            requests: peer_request,
        };
        let encoded = peer_meta.as_ssz_bytes();

        let action = outgoing
            .partial_action_from_metadata(peer, Some(&encoded))
            .unwrap();
        // We should send cells [2, 3] (want = request - available = [2,3], and we have [0,2,3])
        assert!(action.send.is_some());
    }

    #[test]
    fn metadata_sets_need_when_peer_has_unknown_cells() {
        let root = Hash256::repeat_byte(1);
        let header = make_header(4);
        // We have cells [0]
        let partial = make_partial_column(root, 4, &[0]);
        let header_sent_set: HeaderSentSet = Arc::new(Mutex::new(HashSet::new()));
        let requests = make_all_one_bitmap(4);
        let outgoing = OutgoingPartialColumn::new(partial, &header, header_sent_set, requests);

        let peer = random_peer_id();

        // Peer has [0, 1, 2] — cells [1, 2] are unknown to us
        let mut peer_available = CellBitmap::<E>::with_capacity(4).unwrap();
        peer_available.set(0, true).unwrap();
        peer_available.set(1, true).unwrap();
        peer_available.set(2, true).unwrap();
        let peer_meta = PartialDataColumnPartsMetadata::<E> {
            available: peer_available.clone(),
            requests: peer_available,
        };
        let encoded = peer_meta.as_ssz_bytes();

        let action = outgoing
            .partial_action_from_metadata(peer, Some(&encoded))
            .unwrap();
        assert!(action.need);
    }
}
