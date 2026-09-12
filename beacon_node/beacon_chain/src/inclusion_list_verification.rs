use strum::AsRefStr;
use types::{ChainSpec, ProgressiveTransactions};

/// EIP-2718 transaction type of blob transaction
const BLOB_TX_TYPE_ID: u8 = 0x03;

#[derive(Debug, PartialEq, Eq, AsRefStr)]
pub enum InclusionListTransactionsError {
    /// A transaction in the inclusion list has zero length
    EmptyTransaction { index: usize },
    /// A transaction in the inclusion list is a blob transaction
    BlobTransaction { index: usize },
    /// The inclusion list exceeds the maximum allowed size
    ListExceedsSizeLimit { size: u64, max: u64 },
}

/// Verify the size bounds the spec places on inclusion list transactions.
pub fn verify_inclusion_list_transactions_bounds(
    transactions: &ProgressiveTransactions,
    spec: &ChainSpec,
) -> Result<(), InclusionListTransactionsError> {
    let max_size = spec.max_transactions_bytes_per_inclusion_list;
    let list_size = transactions.iter().map(|tx| tx.len() as u64).sum();
    if list_size > max_size {
        return Err(InclusionListTransactionsError::ListExceedsSizeLimit {
            size: list_size,
            max: max_size,
        });
    }

    if let Some(index) = transactions.iter().position(|tx| tx.is_empty()) {
        return Err(InclusionListTransactionsError::EmptyTransaction { index });
    }

    Ok(())
}

/// Verify the inclusion list contains no blob transactions
pub fn verify_no_blob_transactions(
    transactions: &ProgressiveTransactions,
) -> Result<(), InclusionListTransactionsError> {
    if let Some(index) = transactions
        .iter()
        .position(|tx| tx.first() == Some(&BLOB_TX_TYPE_ID))
    {
        return Err(InclusionListTransactionsError::BlobTransaction { index });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::ProgressiveVariableList;
    use types::{EthSpec, MinimalEthSpec};

    type E = MinimalEthSpec;

    /// A transaction of `len` non-zero bytes.
    fn tx(len: usize) -> ProgressiveVariableList<u8> {
        ProgressiveVariableList::new(vec![0xaa; len])
    }

    fn transactions(txs: Vec<ProgressiveVariableList<u8>>) -> ProgressiveTransactions {
        ProgressiveVariableList::new(txs)
    }

    #[test]
    fn empty_inclusion_list_is_accepted() {
        assert_eq!(
            verify_inclusion_list_transactions_bounds(&transactions(vec![]), &E::default_spec()),
            Ok(())
        );
    }

    #[test]
    fn inclusion_list_over_the_size_limit_is_rejected() {
        let spec = E::default_spec();
        let max = spec.max_transactions_bytes_per_inclusion_list;
        let size = max + 1;

        assert_eq!(
            verify_inclusion_list_transactions_bounds(
                &transactions(vec![tx(size as usize)]),
                &spec
            ),
            Err(InclusionListTransactionsError::ListExceedsSizeLimit { size, max })
        );
    }

    #[test]
    fn inclusion_list_at_the_size_limit_is_accepted() {
        let spec = E::default_spec();

        assert_eq!(
            verify_inclusion_list_transactions_bounds(
                &transactions(vec![tx(
                    spec.max_transactions_bytes_per_inclusion_list as usize
                )]),
                &spec
            ),
            Ok(())
        );
    }

    #[test]
    fn inclusion_list_with_empty_transaction_is_rejected() {
        let txs = vec![tx(1), ProgressiveVariableList::empty(), tx(1)];
        let spec = E::default_spec();

        assert_eq!(
            verify_inclusion_list_transactions_bounds(&transactions(txs), &spec),
            Err(InclusionListTransactionsError::EmptyTransaction { index: 1 })
        );
    }

    #[test]
    fn valid_inclusion_list_passes_verification() {
        let txs = vec![tx(10); 10];
        let spec = E::default_spec();

        assert_eq!(
            verify_inclusion_list_transactions_bounds(&transactions(txs), &spec),
            Ok(())
        );
    }

    #[test]
    fn inclusion_list_with_blob_transaction_is_rejected() {
        let blob_tx = ProgressiveVariableList::new(vec![BLOB_TX_TYPE_ID, 0xaa]);
        let txs = vec![tx(10), blob_tx, tx(10)];

        assert_eq!(
            verify_no_blob_transactions(&transactions(txs)),
            Err(InclusionListTransactionsError::BlobTransaction { index: 1 })
        );
    }

    #[test]
    fn inclusion_list_without_blob_transactions_is_accepted() {
        let txs = vec![tx(10); 3];

        assert_eq!(verify_no_blob_transactions(&transactions(txs)), Ok(()));
    }
}
