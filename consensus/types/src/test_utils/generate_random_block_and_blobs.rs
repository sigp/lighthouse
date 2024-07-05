use rand::Rng;

use kzg::{KzgCommitment, KzgProof};

use crate::beacon_block_body::KzgCommitments;
use crate::*;

use super::*;

type BlobsBundle<E> = (KzgCommitments<E>, KzgProofs<E>, BlobsList<E>);

pub fn generate_rand_block_and_blobs<E: EthSpec>(
    fork_name: ForkName,
    num_blobs: usize,
    rng: &mut impl Rng,
) -> (SignedBeaconBlock<E, FullPayload<E>>, Vec<BlobSidecar<E>>) {
    let inner = map_fork_name!(fork_name, BeaconBlock, <_>::random_for_test(rng));
    let mut block = SignedBeaconBlock::from_block(inner, Signature::random_for_test(rng));
    let mut blob_sidecars = vec![];

    if block.fork_name_unchecked() < ForkName::Deneb {
        return (block, blob_sidecars);
    }

    let (commitments, proofs, blobs) = generate_blobs::<E>(num_blobs).unwrap();
    *block
        .message_mut()
        .body_mut()
        .blob_kzg_commitments_mut()
        .expect("kzg commitment expected from Deneb") = commitments.clone();

    for (index, ((blob, kzg_commitment), kzg_proof)) in blobs
        .into_iter()
        .zip(commitments.into_iter())
        .zip(proofs.into_iter())
        .enumerate()
    {
        blob_sidecars.push(BlobSidecar {
            index: index as u64,
            blob: blob.clone(),
            kzg_commitment,
            kzg_proof,
            signed_block_header: block.signed_block_header(),
            kzg_commitment_inclusion_proof: block
                .message()
                .body()
                .kzg_commitment_merkle_proof(index)
                .unwrap(),
        });
    }
    (block, blob_sidecars)
}

pub fn generate_blobs<E: EthSpec>(n_blobs: usize) -> Result<BlobsBundle<E>, String> {
    let (mut commitments, mut proofs, mut blobs) = BlobsBundle::<E>::default();

    for blob_index in 0..n_blobs {
        blobs
            .push(Blob::<E>::default())
            .map_err(|_| format!("blobs are full, blob index: {:?}", blob_index))?;
        commitments
            .push(KzgCommitment::empty_for_testing())
            .map_err(|_| format!("blobs are full, blob index: {:?}", blob_index))?;
        proofs
            .push(KzgProof::empty())
            .map_err(|_| format!("blobs are full, blob index: {:?}", blob_index))?;
    }

    Ok((commitments, proofs, blobs))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_verify_blob_inclusion_proof() {
        let (_block, blobs) =
            generate_rand_block_and_blobs::<MainnetEthSpec>(ForkName::Deneb, 6, &mut thread_rng());
        for blob in blobs {
            assert!(blob.verify_blob_sidecar_inclusion_proof());
        }
    }

    #[test]
    fn test_verify_blob_inclusion_proof_invalid() {
        let (_block, blobs) =
            generate_rand_block_and_blobs::<MainnetEthSpec>(ForkName::Deneb, 6, &mut thread_rng());

        for mut blob in blobs {
            blob.kzg_commitment_inclusion_proof = FixedVector::random_for_test(&mut thread_rng());
            assert!(!blob.verify_blob_sidecar_inclusion_proof());
        }
    }
}
