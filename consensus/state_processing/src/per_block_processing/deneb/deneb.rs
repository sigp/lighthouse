use ethereum_hashing::hash_fixed;
use types::consts::deneb::VERSIONED_HASH_VERSION_KZG;
use types::{KzgCommitment, VersionedHash};

pub fn kzg_commitment_to_versioned_hash(kzg_commitment: &KzgCommitment) -> VersionedHash {
    let mut hashed_commitment = hash_fixed(&kzg_commitment.0);
    hashed_commitment[0] = VERSIONED_HASH_VERSION_KZG;
    VersionedHash::from(hashed_commitment)
}
