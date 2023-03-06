use std::collections::{BTreeMap, HashMap};
use kzg::KzgCommitment;
use ssz_types::VariableList;
use types::blob_sidecar::{BlobIdentifier, BlobSidecar};
use types::{EthSpec, Hash256};
use crate::blob_verification::verify_data_availability;

/// Only need to put when we get a blob
/// Only need to get when we have a block we want to verify
pub struct GossipBlobCache<T: EthSpec> {
    sender: tokio::sync::mpsc::Sender<Operation<T>>,
    thread: tokio::task::JoinHandle<()>,
}

pub enum Operation<T: EthSpec> {
    DataAvailabilityCheck(DataAvailabilityRequest<T>),
    Put(BlobSidecar<T>),
}

pub struct DataAvailabilityRequest<T: EthSpec> {
    block_root: Hash256,
    kzg_commitments: VariableList<KzgCommitment, T::MaxBlobsPerBlock>,
    sender: oneshot_broadcast::Sender<VariableList<BlobSidecar<T>,  T::MaxBlobsPerBlock>>,
}

impl <T: EthSpec> GossipBlobCache<T> {
    pub fn new() -> Self {
        //TODO(sean) figure out capacity

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Operation<T>>(1000);


        let thread = tokio::task::spawn(async move || {
            let mut unverified_blobs: BTreeMap<BlobIdentifier, BlobSidecar<T>> = BTreeMap::new();
            let mut verified_blobs: HashMap<Hash256, VariableList<BlobSidecar<T>, T::MaxBlobsPerBlock>>= HashMap::new();
            let mut requests: HashMap<Hash256, DataAvailabilityRequest<T>> = HashMap::new();
            while let Some(op) = rx.recv().await {
                // check if we already have a verified set of blobs for this, if so ignore
                // check if we can complete a set of blobs and verify
                // -- if yes, do it, then check if there are outstanding requests we can resolve, and resolve them
                // -- -- spawn a thread that does verification
                // -- if no, add to unverified blobs

                match op {
                    Operation::Put(blob) => {
                        let blob_id = blob.id();
                        if !unverified_blobs.contains_key(&blob_id) {
                            unverified_blobs.insert(blob_id, blob)
                        }

                        if !verified_blobs.contains_key(&blob.block_root) {
                            // ignore
                            if let Some(request) = requests.get(&blob.block_root) {
                                let expected_blob_count = request.kzg_commitments.len();

                                let mut blobs = unverified_blobs.range(BlobIdentifier::new(blob.block_root, 0)..BlobIdentifier::new(blob.block_root, expected_blob_count as u64));

                                for (index, (_, blob)) in blobs.enumerate() {
                                    // find missing blobs and trigger a request
                                }

                                verify_data_availability(blob, request.kzg_commitments);
                                verified_blobs.put(blob.block_root, blob);

                                request.sender.send(result)
                            }
                            // check if the request can be completed, and if so complete it
                        }
                    }
                    Operation::DataAvailabilityCheck(request) => {
                        if let Some(verified_blobs) = verified_blobs.get(&blob.block_root) {
                            request.sender.send(result)
                        } else {
                            requests.insert(request.block_root, request)
                        }
                    }
                    Operation::GetBlobById(id) => {
                        unverified_blobs.get(id)
                    }
                    Operation::GetBlobsByBlockRoot((root, count)) => {

                    }
                }

            }
        });
        Self {
            sender: tx,
            thread,
        }
    }

    pub fn put(&self, blob: BlobSidecar<T>) {
        self.sender.send(Operation::Put(blob));
    }

    pub async fn get_verified(&self, block_root: Hash256, kzg_commitments: VariableList<KzgCommitment, T::MaxBlobsPerBlock>) -> Receiever<VariableList<BlobSidecar<T>, T::MaxBlobsPerBlock>> {
        // check if there are verified blobs
        // if not, check if not check if there's a request for this block already.
        // -- if yes, await the join handle return
        // -- if no, create new request entry (spawn a new thread?)
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = DataAvailabilityRequest {
            block_root,
            kzg_commitments,
            sender: tx,
        };
        self.sender.send(Operation::DataAvailabilityCheck(req));
        rx
    }
}
