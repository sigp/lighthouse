use super::Hash256;

#[derive(Debug, PartialEq)]
pub struct CandidatePoWReceiptRootRecord {
    pub candidate_pow_receipt_root: Hash256,
    pub votes: u64,
}
