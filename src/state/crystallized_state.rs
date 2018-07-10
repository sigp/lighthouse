use super::utils::types::{ Sha256Digest, Blake2sDigest };
use super::validator_record::ValidatorRecord;
use super::crosslink_record::CrosslinkRecord;
use super::rlp::{ RlpStream, Encodable };
use super::rlp::encode as rlp_encode;
use super::ethereum_types::U256;
use super::blake2::{ Blake2s, Digest };

pub struct CrystallizedState {
    pub active_validators: Vec<ValidatorRecord>,
    pub queued_validators: Vec<ValidatorRecord>,
    pub exited_validators: Vec<ValidatorRecord>,
    pub current_shuffling: Vec<u32>,  // TODO: should be u24
    pub current_epoch: u64,
    pub last_justified_epoch: u64,
    pub last_finalized_epoch: u64,
    pub dynasty: u64,
    pub next_shard: u16,
    pub current_checkpoint: Sha256Digest,
    pub crosslink_records: Vec<CrosslinkRecord>,
    pub total_deposits: U256,
}

impl CrystallizedState {
    pub fn num_active_validators(&self) -> usize {
        self.active_validators.len()
    }

    pub fn num_queued_validators(&self) -> usize {
        self.queued_validators.len()
    }

    pub fn num_exited_validators(&self) -> usize {
        self.exited_validators.len()
    }

    pub fn num_crosslink_records(&self) -> usize {
        self.crosslink_records.len()

    }
    
    pub fn blake2s_hash(&self) -> Blake2sDigest {
        let mut hasher = Blake2s::new();
        hasher.input(&rlp_encode(self).into_vec());
        let mut digest = Blake2sDigest::new();
        digest.clone_from_slice(hasher.result().as_slice());
        digest
    }
}

/*
 * RLP Encoding
 */
impl Encodable for CrystallizedState {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_list(&self.active_validators);
        s.append_list(&self.queued_validators);
        s.append_list(&self.exited_validators);
        s.append_list(&self.current_shuffling);
        s.append(&self.current_epoch);
        s.append(&self.last_justified_epoch);
        s.append(&self.last_finalized_epoch);
        s.append(&self.dynasty);
        s.append(&self.next_shard);
        s.append(&self.current_checkpoint);
        s.append_list(&self.crosslink_records);
        s.append(&self.total_deposits);
    }
}

#[cfg(test)]
mod tests {
    use super::super::rlp;
    use super::*;

    #[test]
    fn test_serialization() {
        let a = CrystallizedState {
            active_validators: Vec::new(),
            queued_validators: Vec::new(),
            exited_validators: Vec::new(),
            current_shuffling: Vec::new(),
            current_epoch: 10,
            last_justified_epoch: 8,
            last_finalized_epoch: 2,
            dynasty: 3,
            next_shard: 12,
            current_checkpoint: Sha256Digest::zero(),
            crosslink_records: Vec::new(),
            total_deposits: U256::zero(),
        };
        let e = rlp::encode(&a);
        assert_eq!(e.len(), 44);
        assert_eq!(e[0..4], [192; 4]);
        assert_eq!(e[4], 10);
        assert_eq!(e[5], 8);
        assert_eq!(e[6], 2);
        assert_eq!(e[7], 3);
        assert_eq!(e[8], 12);
        assert_eq!(e[9], 160);
        assert_eq!(e[10..42], [0; 32]);
        assert_eq!(e[42], 192);
        assert_eq!(e[43], 128);
    }
}
