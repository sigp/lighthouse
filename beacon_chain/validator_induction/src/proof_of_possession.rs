use bls::{
    Signature,
    PublicKey,
};
use hashing::proof_of_possession_hash;

/// For some signature and public key, ensure that the signature message was the public key and it
/// was signed by the secret key that corresponds to that public key.
pub fn verify_proof_of_possession(sig: &Signature, pubkey: &PublicKey)
    -> bool
{
    let hash = proof_of_possession_hash(&pubkey.as_bytes());
    sig.verify_hashed(&hash, &pubkey)
}
