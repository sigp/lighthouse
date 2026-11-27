mod deposit;
mod deposit_data;
mod deposit_message;
mod deposit_request;
mod deposit_tree_snapshot;
mod pending_deposit;

use crate::{Hash256, XmssPublicKey};
use alloy_primitives::keccak256;
use bls::{PUBLIC_KEY_BYTES_LEN, PublicKeyBytes, SignatureBytes};

pub use deposit::{DEPOSIT_TREE_DEPTH, Deposit};
pub use deposit_data::DepositData;
pub use deposit_message::DepositMessage;
pub use deposit_request::DepositRequest;
pub use deposit_tree_snapshot::{DepositTreeSnapshot, FinalizedExecutionBlock};
pub use pending_deposit::PendingDeposit;

const PQ_DEPOSIT_PREFIX: [u8; 16] = [0; 16];
const LEGACY_XMSS_PUBKEY_DOMAIN: [u8; 1] = [0];
const LEGACY_VRF_ROOT_DOMAIN: [u8; 1] = [1];

/// A legacy request names a BLS key instead of an XMSS key with its zero prefix.
pub fn is_legacy_deposit_pubkey(pubkey: &PublicKeyBytes) -> bool {
    !pubkey.as_serialized().starts_with(&PQ_DEPOSIT_PREFIX)
}

/// Map a deposit key in the unchanged 48-byte request format to its registry key.
pub fn compute_deposit_pubkey(pubkey: &PublicKeyBytes) -> XmssPublicKey {
    if let Some((prefix, key)) = pubkey.as_serialized().split_last_chunk::<32>()
        && prefix == PQ_DEPOSIT_PREFIX
    {
        return (*key).into();
    }

    keccak256([pubkey.as_serialized(), &LEGACY_XMSS_PUBKEY_DOMAIN].concat())
        .0
        .into()
}

/// Read the VRF commitment of a PQ deposit or compute the legacy deposit commitment.
pub fn compute_deposit_vrf_root(pubkey: &PublicKeyBytes, signature: &SignatureBytes) -> Hash256 {
    if !is_legacy_deposit_pubkey(pubkey)
        && let Some(root) = signature.serialize().first_chunk::<32>()
    {
        return (*root).into();
    }

    keccak256([pubkey.as_serialized(), &LEGACY_VRF_ROOT_DOMAIN].concat())
        .0
        .into()
}

/// Represent a registry key in the 48-byte deposit key format.
pub fn encode_deposit_pubkey(pubkey: XmssPublicKey) -> Result<PublicKeyBytes, bls::Error> {
    let mut bytes = [0; PUBLIC_KEY_BYTES_LEN];
    for (byte, key_byte) in bytes
        .iter_mut()
        .skip(PQ_DEPOSIT_PREFIX.len())
        .zip(pubkey.to_bytes())
    {
        *byte = key_byte;
    }
    PublicKeyBytes::deserialize(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_registry_identity() {
        let xmss_pubkey = XmssPublicKey::from([7; 32]);
        let deposit_pubkey = encode_deposit_pubkey(xmss_pubkey).unwrap();
        let deposit_signature = SignatureBytes::deserialize(&[8; 96]).unwrap();
        assert_eq!(
            deposit_pubkey.as_serialized(),
            [[0; 16].as_slice(), &[7; 32]].concat()
        );
        assert_eq!(compute_deposit_pubkey(&deposit_pubkey), xmss_pubkey);
        assert_eq!(
            compute_deposit_vrf_root(&deposit_pubkey, &deposit_signature),
            Hash256::repeat_byte(8)
        );

        let legacy_pubkey = PublicKeyBytes::deserialize(&[9; 48]).unwrap();
        assert_eq!(
            compute_deposit_pubkey(&legacy_pubkey),
            "0xa1fc67d0715e7a9d5ef9500cb48db0a97e6ea75ae0f415534ac6278103275930"
                .parse::<XmssPublicKey>()
                .unwrap()
        );
        assert_eq!(
            compute_deposit_vrf_root(&legacy_pubkey, &deposit_signature),
            "0x90ed2a255339d9034607dd7db88e076707bd8e4f1362f17d2f8a931a012b9e1e"
                .parse::<Hash256>()
                .unwrap()
        );
    }
}
