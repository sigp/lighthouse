use alloy_consensus::TxEnvelope;
use alloy_rlp::Decodable;
use types::{EthSpec, ExecutionPayloadRef, Hash256, Unsigned, VersionedHash};

#[derive(Debug)]
pub enum Error {
    DecodingTransaction(String),
    LengthMismatch { expected: usize, found: usize },
    VersionHashMismatch { expected: Hash256, found: Hash256 },
}

pub fn verify_versioned_hashes<E: EthSpec>(
    execution_payload: ExecutionPayloadRef<E>,
    expected_versioned_hashes: &[VersionedHash],
) -> Result<(), Error> {
    let versioned_hashes =
        extract_versioned_hashes_from_transactions::<E>(execution_payload.transactions())?;
    if versioned_hashes.len() != expected_versioned_hashes.len() {
        return Err(Error::LengthMismatch {
            expected: expected_versioned_hashes.len(),
            found: versioned_hashes.len(),
        });
    }
    for (found, expected) in versioned_hashes
        .iter()
        .zip(expected_versioned_hashes.iter())
    {
        if found != expected {
            return Err(Error::VersionHashMismatch {
                expected: *expected,
                found: *found,
            });
        }
    }

    Ok(())
}

pub fn extract_versioned_hashes_from_transactions<E: EthSpec>(
    transactions: &types::Transactions<E>,
) -> Result<Vec<VersionedHash>, Error> {
    let mut versioned_hashes = Vec::new();

    for tx in transactions {
        match beacon_tx_to_tx_envelope(tx)? {
            TxEnvelope::Eip4844(signed_tx_eip4844) => {
                versioned_hashes.extend(
                    signed_tx_eip4844
                        .tx()
                        .blob_versioned_hashes
                        .iter()
                        .map(|fb| Hash256::from(fb.0)),
                );
            }
            // enumerating all variants explicitly to make pattern irrefutable
            // in case new types are added in the future which also have blobs
            TxEnvelope::Legacy(_)
            | TxEnvelope::TaggedLegacy(_)
            | TxEnvelope::Eip2930(_)
            | TxEnvelope::Eip1559(_) => {}
        }
    }

    Ok(versioned_hashes)
}

pub fn beacon_tx_to_tx_envelope<N: Unsigned>(
    tx: &types::Transaction<N>,
) -> Result<TxEnvelope, Error> {
    let tx_bytes = Vec::from(tx.clone());
    TxEnvelope::decode(&mut tx_bytes.as_slice())
        .map_err(|e| Error::DecodingTransaction(e.to_string()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::static_valid_tx;
    use alloy_consensus::{TxKind, TxLegacy};

    type E = types::MainnetEthSpec;

    #[test]
    fn test_decode_static_transaction() {
        let valid_tx = static_valid_tx::<E>().expect("should give me known valid transaction");
        let tx_envelope = beacon_tx_to_tx_envelope(&valid_tx).expect("should decode tx");
        let TxEnvelope::Legacy(signed_tx) = tx_envelope else {
            panic!("should decode to legacy transaction");
        };

        assert!(matches!(
            signed_tx.tx(),
            TxLegacy {
                chain_id: Some(0x01),
                nonce: 0x15,
                gas_price: 0x4a817c800,
                to: TxKind::Call(..),
                ..
            }
        ));
    }

    #[test]
    fn test_extract_versioned_hashes() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        #[serde(transparent)]
        struct TestTransactions<E: EthSpec>(
            #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")] types::Transactions<E>,
        );

        let TestTransactions(raw_transactions): TestTransactions<E> = serde_json::from_str(r#"[
            "0x03f901388501a1f0ff430f843b9aca00843b9aca0082520894e7249813d8ccf6fa95a2203f46a64166073d58878080c002f8c6a0012e98362c814f1724262c0d211a1463418a5f6382a8d457b37a2698afbe7b5ea00100ef985761395dfa8ed5ce91f3f2180b612401909e4cb8f33b90c8a454d9baa0013d45411623b90d90f916e4025ada74b453dd4ca093c017c838367c9de0f801a001753e2af0b1e70e7ef80541355b2a035cc9b2c177418bb2a4402a9b346cf84da0011789b520a8068094a92aa0b04db8d8ef1c6c9818947c5210821732b8744049a0011c4c4f95597305daa5f62bf5f690e37fa11f5de05a95d05cac4e2119e394db80a0ccd86a742af0e042d08cbb35d910ddc24bbc6538f9e53be6620d4b6e1bb77662a01a8bacbc614940ac2f5c23ffc00a122c9f085046883de65c88ab0edb859acb99",
            "0x02f9017a8501a1f0ff4382363485012a05f2008512a05f2000830249f094c1b0bc605e2c808aa0867bfc98e51a1fe3e9867f80b901040cc7326300000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000009445a285baa43e00000000000000000000000000c500931f24edb821cef6e28f7adb33b38578c82000000000000000000000000fc7360b3b28cf4204268a8354dbec60720d155d2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000009a054a063f0fe7b9c68de8df91aaa5e96c15ab540000000000000000000000000c8d41b8fcc066cdabaf074d78e5153e8ce018a9c080a008e14475c1173cd9f5740c24c08b793f9e16c36c08fa73769db95050e31e3396a019767dcdda26c4a774ca28c9df15d0c20e43bd07bd33ee0f84d6096cb5a1ebed"
        ]"#).expect("should get raw transactions");
        let expected_versioned_hashes = vec![
            "0x012e98362c814f1724262c0d211a1463418a5f6382a8d457b37a2698afbe7b5e",
            "0x0100ef985761395dfa8ed5ce91f3f2180b612401909e4cb8f33b90c8a454d9ba",
            "0x013d45411623b90d90f916e4025ada74b453dd4ca093c017c838367c9de0f801",
            "0x01753e2af0b1e70e7ef80541355b2a035cc9b2c177418bb2a4402a9b346cf84d",
            "0x011789b520a8068094a92aa0b04db8d8ef1c6c9818947c5210821732b8744049",
            "0x011c4c4f95597305daa5f62bf5f690e37fa11f5de05a95d05cac4e2119e394db",
        ]
        .into_iter()
        .map(|tx| Hash256::from_slice(&hex::decode(&tx[2..]).expect("should decode hex")))
        .collect::<Vec<_>>();

        let versioned_hashes = extract_versioned_hashes_from_transactions::<E>(&raw_transactions)
            .expect("should get versioned hashes");
        assert_eq!(versioned_hashes, expected_versioned_hashes);
    }
}
