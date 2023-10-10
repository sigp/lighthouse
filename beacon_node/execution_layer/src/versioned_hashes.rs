extern crate reth_primitives;
extern crate reth_rlp;

use reth_primitives::{Transaction, TransactionSigned};
use reth_rlp::Decodable;
use std::collections::HashSet;
use types::{EthSpec, ExecutionPayloadRef, Hash256, Unsigned, VersionedHash};

#[derive(Debug)]
pub enum Error {
    DecodingTransaction(String),
    LengthMismatch { expected: usize, found: usize },
    MissingHash(VersionedHash),
}

pub fn verify_versioned_hashes<E: EthSpec>(
    execution_payload: ExecutionPayloadRef<E>,
    expected_versioned_hashes: &Vec<VersionedHash>,
) -> Result<(), Error> {
    match execution_payload {
        ExecutionPayloadRef::Merge(_) | ExecutionPayloadRef::Capella(_) => Ok(()),
        ExecutionPayloadRef::Deneb(payload) => {
            let versioned_hashes = get_versioned_hashes::<E>(&payload.transactions)?;
            // ensure that all expected hashes are present
            for expected_hash in expected_versioned_hashes {
                if !versioned_hashes.contains(expected_hash) {
                    return Err(Error::MissingHash(*expected_hash));
                }
            }
            // ensure that there are no extra hashes
            if versioned_hashes.len() != expected_versioned_hashes.len() {
                return Err(Error::LengthMismatch {
                    expected: expected_versioned_hashes.len(),
                    found: versioned_hashes.len(),
                });
            }
            Ok(())
        }
    }
}

pub fn get_versioned_hashes<E: EthSpec>(
    transactions: &types::Transactions<E>,
) -> Result<HashSet<VersionedHash>, Error> {
    Ok(transactions
        .into_iter()
        .map(beacon_tx_to_reth_signed_tx)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|tx| match tx.transaction {
            Transaction::Eip4844(blob_tx) => Some(blob_tx.blob_versioned_hashes),
            _ => None,
        })
        .flatten()
        .map(Hash256::from)
        .collect())
}

pub fn beacon_tx_to_reth_signed_tx<N: Unsigned>(
    tx: &types::Transaction<N>,
) -> Result<TransactionSigned, Error> {
    let tx_bytes = Vec::from(tx.clone());
    TransactionSigned::decode(&mut tx_bytes.as_slice())
        .map_err(|e| Error::DecodingTransaction(e.to_string()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::static_valid_tx;
    use reth_primitives::Transaction;

    #[test]
    fn test_decode_reth_transaction() {
        type E = types::MainnetEthSpec;
        let valid_tx = static_valid_tx::<E>().expect("should give me known valid transaction");
        let tx = beacon_tx_to_reth_signed_tx(&valid_tx).expect("should decode tx");
        assert!(matches!(
            tx.transaction,
            Transaction::Legacy(reth_primitives::TxLegacy {
                chain_id: Some(0x01),
                nonce: 0x15,
                gas_price: 0x4a817c800,
                to: reth_primitives::TransactionKind::Call(..),
                ..
            })
        ));
    }
}
