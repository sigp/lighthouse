//! Statements as leanVM claims.
//!
//! An aggregate proof attests a set of `(pubkey, message)` claims. The verifier only accepts
//! a claim list that is strictly sorted by the 64 bytes `pubkey || message`, so statements
//! flatten to the sorted, de-duplicated list of their `(pubkey, message)` pairs. The leaf
//! index is not part of a claim.

use crate::Statement;
use lean_xmss::LeanXmssPublicKey;
use leanvm_claims::AggregateClaims;
use xmss::{XMSS_MESSAGE_BYTES_LEN, XMSS_PUBLIC_KEY_BYTES_LEN};

/// The claims a proof of `statements` attests: every `(pubkey, message)` pair, strictly
/// sorted by its bytes, without duplicates. No leanSPHINCS claims and no DA commitment.
pub fn statements_to_claims(statements: &[Statement]) -> AggregateClaims {
    let mut pairs: Vec<(
        [u8; XMSS_PUBLIC_KEY_BYTES_LEN],
        [u8; XMSS_MESSAGE_BYTES_LEN],
    )> = statements
        .iter()
        .flat_map(|statement| {
            statement
                .pubkeys
                .iter()
                .map(|pubkey| (pubkey.to_bytes(), statement.message))
        })
        .collect();
    // Tuples of byte arrays order as their concatenation does.
    pairs.sort_unstable();
    pairs.dedup();
    AggregateClaims {
        lean_xmss: pairs
            .into_iter()
            .map(|(pubkey, message)| (LeanXmssPublicKey::from_bytes(&pubkey), message))
            .collect(),
        lean_sphincs: Vec::new(),
        da_commitment: None,
    }
}

/// [`statements_to_claims`] in leanVM's byte form (`AggregateClaims::to_bytes`):
///
/// | field | type |
/// | --- | --- |
/// | leanXMSS claims | `u64` LE count, then per claim: pubkey (32 bytes), message (32 bytes) |
/// | leanSPHINCS claims | `u64` LE count (always 0 here) |
/// | DA commitment | `u8` 0 (none) |
pub fn statements_to_claims_bytes(statements: &[Statement]) -> Vec<u8> {
    statements_to_claims(statements).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmss::XmssPublicKey;

    fn pubkey(byte: u8) -> XmssPublicKey {
        XmssPublicKey::from([byte; 32])
    }

    #[test]
    fn empty_statements() {
        // Zero leanXMSS claims, zero leanSPHINCS claims, no DA commitment.
        let expected = [0u8; 8 + 8 + 1];
        assert_eq!(statements_to_claims_bytes(&[]), expected);
        // Statements without public keys claim nothing either.
        let statement = Statement {
            pubkeys: vec![],
            leaf_index: 1,
            message: [7; 32],
        };
        assert_eq!(statements_to_claims_bytes(&[statement]), expected);
    }

    #[test]
    fn claims_bytes_match_the_leanvm_format() {
        // Out of order within and across statements, with one repeated claim, and one key
        // signing two messages. The leaf index does not appear.
        let mut low_key = [3; 32];
        low_key[31] = 2;
        let statements = [
            Statement {
                pubkeys: vec![pubkey(9), pubkey(3), XmssPublicKey::from(low_key)],
                leaf_index: 40_000,
                message: [0xaa; 32],
            },
            Statement {
                pubkeys: vec![pubkey(3), pubkey(1)],
                leaf_index: 50_000,
                message: [0x11; 32],
            },
            Statement {
                pubkeys: vec![pubkey(9)],
                leaf_index: 60_000,
                message: [0xaa; 32],
            },
        ];

        // Written out by hand from the format in leanVM's canonical claims format.
        let mut expected = Vec::new();
        expected.extend_from_slice(&5u64.to_le_bytes());
        for (key, message) in [
            ([1; 32], [0x11; 32]),
            (low_key, [0xaa; 32]),
            ([3; 32], [0x11; 32]),
            ([3; 32], [0xaa; 32]),
            ([9; 32], [0xaa; 32]),
        ] {
            expected.extend_from_slice(&key);
            expected.extend_from_slice(&message);
        }
        expected.extend_from_slice(&0u64.to_le_bytes());
        expected.push(0);

        let bytes = statements_to_claims_bytes(&statements);
        assert_eq!(bytes.len(), 8 + 5 * 64 + 8 + 1);
        assert_eq!(bytes, expected);

        // Strictly sorted by the 64 bytes of each claim.
        let claims: Vec<&[u8]> = bytes[8..8 + 5 * 64].chunks(64).collect();
        assert!(claims.windows(2).all(|pair| pair[0] < pair[1]));

        // Upstream's decoder reads it back.
        let decoded = AggregateClaims::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, statements_to_claims(&statements));
        assert_eq!(decoded.num_signature_claims(), 5);
    }

    #[test]
    fn statement_order_does_not_matter() {
        let first = Statement {
            pubkeys: vec![pubkey(1), pubkey(2)],
            leaf_index: 5,
            message: [4; 32],
        };
        let second = Statement {
            pubkeys: vec![pubkey(3)],
            leaf_index: 5,
            message: [3; 32],
        };
        assert_eq!(
            statements_to_claims_bytes(&[first.clone(), second.clone()]),
            statements_to_claims_bytes(&[second, first])
        );
    }
}
