use arbitrary::Arbitrary;
use kzg::{KzgCommitment, KzgProof};

use crate::{
    block::{BeaconBlock, SignedBeaconBlock},
    core::{EthSpec, MainnetEthSpec},
    data::{Blob, BlobSidecar, BlobsList},
    execution::FullPayload,
    fork::{ForkName, map_fork_name},
    kzg_ext::{KzgCommitments, KzgProofs},
};

type BlobsBundle<E> = (KzgCommitments<E>, KzgProofs<E>, BlobsList<E>);

#[allow(clippy::type_complexity)]
pub fn generate_rand_block_and_blobs<E: EthSpec>(
    fork_name: ForkName,
    num_blobs: usize,
    u: &mut arbitrary::Unstructured,
) -> arbitrary::Result<(SignedBeaconBlock<E, FullPayload<E>>, Vec<BlobSidecar<E>>)> {
    let inner = map_fork_name!(fork_name, BeaconBlock, <_>::arbitrary(u)?);
    let mut block = SignedBeaconBlock::from_block(inner, bls::Signature::arbitrary(u)?);
    let mut blob_sidecars = vec![];

    if block.fork_name_unchecked() < ForkName::Deneb {
        return Ok((block, blob_sidecars));
    }

    let (commitments, proofs, blobs) = generate_blobs::<E>(num_blobs).unwrap();
    *block
        .message_mut()
        .body_mut()
        .blob_kzg_commitments_mut()
        .expect("kzg commitment expected from Deneb") = commitments.clone();

    for (index, ((blob, kzg_commitment), kzg_proof)) in
        blobs.into_iter().zip(commitments).zip(proofs).enumerate()
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
    Ok((block, blob_sidecars))
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
    use ssz_types::FixedVector;

    #[test]
    fn test_verify_blob_inclusion_proof() {
        let mut u = crate::test_utils::test_unstructured();
        let (_block, blobs) =
            generate_rand_block_and_blobs::<MainnetEthSpec>(ForkName::Deneb, 2, &mut u).unwrap();
        for blob in blobs {
            assert!(blob.verify_blob_sidecar_inclusion_proof());
        }
    }

    #[test]
    fn test_verify_blob_inclusion_proof_from_existing_proof() {
        let mut u = crate::test_utils::test_unstructured();
        let (block, mut blob_sidecars) =
            generate_rand_block_and_blobs::<MainnetEthSpec>(ForkName::Deneb, 1, &mut u).unwrap();
        let BlobSidecar {
            index,
            blob,
            kzg_proof,
            ..
        } = blob_sidecars.pop().unwrap();

        let blob_sidecar =
            BlobSidecar::new_with_existing_proof(index as usize, blob, &block, kzg_proof).unwrap();

        assert!(blob_sidecar.verify_blob_sidecar_inclusion_proof());
    }

    #[test]
    fn test_verify_blob_inclusion_proof_invalid() {
        let mut u = crate::test_utils::test_unstructured();
        let (_block, blobs) =
            generate_rand_block_and_blobs::<MainnetEthSpec>(ForkName::Deneb, 1, &mut u).unwrap();

        for mut blob in blobs {
            blob.kzg_commitment_inclusion_proof = FixedVector::arbitrary(&mut u).unwrap();
            assert!(!blob.verify_blob_sidecar_inclusion_proof());
        }
    }
}
