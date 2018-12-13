use super::Hash256;

#[derive(Debug, PartialEq, Clone)]
pub struct CandidatePoWReceiptRootRecord {
    pub candidate_pow_receipt_root: Hash256,
    pub votes: u64,
}
