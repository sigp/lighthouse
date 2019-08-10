extern crate bytes;
extern crate hashing;
extern crate types;

use bytes::{BufMut, BytesMut};
use eth2_hashing::canonical_hash;
use ssz::ssz_encode;
use std::cmp::max;
use types::{Hash256, ValidatorRecord, ValidatorStatus};

pub enum UpdateValidatorSetError {
    ArithmeticOverflow,
}

const VALIDATOR_FLAG_ENTRY: u8 = 0;
const VALIDATOR_FLAG_EXIT: u8 = 1;

pub fn update_validator_set(
    validators: &mut Vec<ValidatorRecord>,
    hash_chain: Hash256,
    present_slot: u64,
    deposit_size_gwei: u64,
    max_validator_churn_quotient: u64,
) -> Result<(), UpdateValidatorSetError> {
    /*
     * Total balance of all active validators.
     *
     * Return an error if an overflow occurs.
     */
    let total_balance = {
        let mut bal: u64 = 0;
        for v in validators.iter() {
            if v.status_is(ValidatorStatus::Active) {
                bal = bal
                    .checked_add(v.balance)
                    .ok_or(UpdateValidatorSetError::ArithmeticOverflow)?;
            }
        }
        bal
    };

    /*
     * Note: this is not the maximum allowable change, it can actually be higher.
     */
    let max_allowable_change = {
        let double_deposit_size = deposit_size_gwei
            .checked_mul(2)
            .ok_or(UpdateValidatorSetError::ArithmeticOverflow)?;
        max(
            double_deposit_size,
            total_balance / max_validator_churn_quotient,
        )
    };

    let mut hasher = ValidatorChangeHashChain {
        bytes: hash_chain.to_vec(),
    };
    let mut total_changed: u64 = 0;
    for (i, v) in validators.iter_mut().enumerate() {
        match v.status {
            /*
             * Validator is pending activation.
             */
            ValidatorStatus::PendingActivation => {
                let new_total_changed = total_changed
                    .checked_add(deposit_size_gwei)
                    .ok_or(UpdateValidatorSetError::ArithmeticOverflow)?;
                /*
                 * If entering this validator would not exceed the max balance delta,
                 * activate the validator.
                 */
                if new_total_changed <= max_allowable_change {
                    v.status = ValidatorStatus::Active;
                    hasher.extend(i, &ssz_encode(&v.pubkey), VALIDATOR_FLAG_ENTRY);
                    total_changed = new_total_changed;
                } else {
                    // Entering the validator would exceed the balance delta.
                    break;
                }
            }
            /*
             * Validator is pending exit.
             */
            ValidatorStatus::PendingExit => {
                let new_total_changed = total_changed
                    .checked_add(v.balance)
                    .ok_or(UpdateValidatorSetError::ArithmeticOverflow)?;
                /*
                 * If exiting this validator would not exceed the max balance delta,
                 * exit the validator
                 */
                if new_total_changed <= max_allowable_change {
                    v.status = ValidatorStatus::PendingWithdraw;
                    v.exit_slot = present_slot;
                    hasher.extend(i, &ssz_encode(&v.pubkey), VALIDATOR_FLAG_EXIT);
                    total_changed = new_total_changed;
                } else {
                    // Exiting the validator would exceed the balance delta.
                    break;
                }
            }
            _ => (),
        };
        if total_changed >= max_allowable_change {
            break;
        }
    }
    Ok(())
}

pub struct ValidatorChangeHashChain {
    bytes: Vec<u8>,
}

impl ValidatorChangeHashChain {
    pub fn extend(&mut self, index: usize, pubkey: &Vec<u8>, flag: u8) {
        let mut message = self.bytes.clone();
        message.append(&mut serialize_validator_change_record(index, pubkey, flag));
        self.bytes = canonical_hash(&message);
    }
}

fn serialize_validator_change_record(index: usize, pubkey: &Vec<u8>, flag: u8) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(68);
    buf.put_u8(flag);
    let index_bytes = {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u64_be(index as u64);
        buf.take()[8 - 3..8].to_vec()
    };
    buf.put(index_bytes);
    buf.put(pubkey);
    buf.take().to_vec()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
