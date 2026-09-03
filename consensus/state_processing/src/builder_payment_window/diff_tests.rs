//! Differential tests: the pure `builder_payment_window` module against the `BeaconState`
//! implementation, driven by the same random operation sequences.
//!
//! Each operation is applied to both a real Gloas `BeaconState` and the model, and after every
//! step the window and the withdrawal queue must be identical. This is what justifies swapping
//! the real code for calls into the module.

use super::{self as model, PendingPayment, PendingWithdrawal};
use crate::per_block_processing::{
    add_builder_payment_weight, record_builder_pending_payment, settle_builder_payment,
};
use crate::per_epoch_processing::single_pass::process_builder_pending_payments;
use beacon_chain::test_utils::BeaconChainHarness;
use proptest::prelude::*;
use std::sync::{Arc, OnceLock};
use types::{
    Address, BeaconState, BuilderPendingWithdrawal, EthSpec, ForkName, MinimalEthSpec, Slot,
};

type E = MinimalEthSpec;

const SLOTS_PER_EPOCH: u64 = 8;
const WINDOW_LEN: usize = 2 * SLOTS_PER_EPOCH as usize;

/// A Gloas genesis state, built once. Each test case works on a clone.
fn genesis_state() -> BeaconState<E> {
    static STATE: OnceLock<BeaconState<E>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            assert_eq!(E::slots_per_epoch(), SLOTS_PER_EPOCH);
            let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
            let harness = BeaconChainHarness::builder(E::default())
                .spec(Arc::new(spec))
                .deterministic_keypairs(8)
                .fresh_ephemeral_store()
                .mock_execution_layer()
                .build();
            harness.get_current_state()
        })
        .clone()
}

fn to_model_withdrawal(w: &BuilderPendingWithdrawal) -> PendingWithdrawal {
    PendingWithdrawal {
        fee_recipient: w.fee_recipient.0.0,
        amount: w.amount,
        builder_index: w.builder_index,
    }
}

fn to_real_withdrawal(w: &PendingWithdrawal) -> BuilderPendingWithdrawal {
    BuilderPendingWithdrawal {
        fee_recipient: Address::from(w.fee_recipient),
        amount: w.amount,
        builder_index: w.builder_index,
    }
}

/// The real state's window and withdrawal queue, in model form.
fn snapshot(state: &BeaconState<E>) -> (Vec<PendingPayment>, Vec<PendingWithdrawal>) {
    let payments = state
        .builder_pending_payments()
        .expect("gloas state")
        .iter()
        .map(|p| PendingPayment {
            weight: p.weight,
            withdrawal: to_model_withdrawal(&p.withdrawal),
            proposer_index: p.proposer_index,
        })
        .collect();
    let withdrawals = state
        .builder_pending_withdrawals()
        .expect("gloas state")
        .iter()
        .map(to_model_withdrawal)
        .collect();
    (payments, withdrawals)
}

#[derive(Debug, Clone)]
enum Op {
    RecordBid {
        slot: u64,
        withdrawal: PendingWithdrawal,
        proposer_index: u64,
    },
    AddWeight {
        index: usize,
        effective_balance: u64,
    },
    Reveal {
        index: usize,
    },
    Transition {
        quorum: u64,
    },
}

/// Indices run one past the window so the out-of-bounds path is exercised on both sides.
fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u64..4 * SLOTS_PER_EPOCH, 0u64..3, 0u64..4, any::<u8>(), 0u64..8).prop_map(
            |(slot, amount, builder_index, fee_byte, proposer_index)| Op::RecordBid {
                slot,
                withdrawal: PendingWithdrawal {
                    fee_recipient: [fee_byte; 20],
                    amount,
                    builder_index,
                },
                proposer_index,
            }
        ),
        3 => (0usize..=WINDOW_LEN, 0u64..1_000).prop_map(|(index, effective_balance)| {
            Op::AddWeight {
                index,
                effective_balance,
            }
        }),
        2 => (0usize..=WINDOW_LEN).prop_map(|index| Op::Reveal { index }),
        1 => (0u64..3_000).prop_map(|quorum| Op::Transition { quorum }),
    ]
}

/// Applies `op` to both sides and returns whether each succeeded.
fn apply(
    op: &Op,
    state: &mut BeaconState<E>,
    payments: &mut [PendingPayment],
    withdrawals: &mut Vec<PendingWithdrawal>,
) -> (bool, bool) {
    match op {
        Op::RecordBid {
            slot,
            withdrawal,
            proposer_index,
        } => {
            let real = record_builder_pending_payment(
                state,
                Slot::new(*slot),
                to_real_withdrawal(withdrawal),
                *proposer_index,
            );
            let model = model::record_bid_payment(
                payments,
                SLOTS_PER_EPOCH,
                *slot,
                *withdrawal,
                *proposer_index,
            );
            (real.is_ok(), model.is_ok())
        }
        Op::AddWeight {
            index,
            effective_balance,
        } => {
            let real = add_builder_payment_weight(state, *index, *effective_balance);
            let model = model::add_attestation_weight(payments, *index, *effective_balance);
            (real.is_ok(), model.is_ok())
        }
        Op::Reveal { index } => {
            let real = settle_builder_payment(state, *index);
            let model = model::pay_on_reveal(payments, withdrawals, *index);
            (real.is_ok(), model.is_ok())
        }
        Op::Transition { quorum } => {
            let real = process_builder_pending_payments(state, *quorum);
            let model =
                model::pay_at_epoch_transition(payments, withdrawals, SLOTS_PER_EPOCH, *quorum);
            (real.is_ok(), model.is_ok())
        }
    }
}

fn run(ops: &[Op]) {
    let mut state = genesis_state();
    let (mut payments, mut withdrawals) = snapshot(&state);
    assert_eq!(payments.len(), WINDOW_LEN);
    assert!(withdrawals.is_empty());

    for (step, op) in ops.iter().enumerate() {
        let (real_ok, model_ok) = apply(op, &mut state, &mut payments, &mut withdrawals);
        assert_eq!(real_ok, model_ok, "step {step}: outcome differs for {op:?}");

        let (real_payments, real_withdrawals) = snapshot(&state);
        assert_eq!(
            real_payments, payments,
            "step {step}: window differs after {op:?}"
        );
        assert_eq!(
            real_withdrawals, withdrawals,
            "step {step}: withdrawals differ after {op:?}"
        );
    }
}

proptest! {
    #[test]
    fn model_matches_state_on_random_operations(
        ops in proptest::collection::vec(op_strategy(), 0..40)
    ) {
        run(&ops);
    }
}

/// A fixed sequence covering every operation, so a divergence has a readable trace.
#[test]
fn model_matches_state_on_fixed_sequence() {
    let withdrawal = |amount, builder_index| PendingWithdrawal {
        fee_recipient: [0xaa; 20],
        amount,
        builder_index,
    };
    run(&[
        Op::RecordBid {
            slot: 5,
            withdrawal: withdrawal(100, 1),
            proposer_index: 3,
        },
        Op::AddWeight {
            index: SLOTS_PER_EPOCH as usize + 5,
            effective_balance: 32,
        },
        Op::RecordBid {
            slot: 6,
            withdrawal: withdrawal(0, 2),
            proposer_index: 4,
        },
        Op::Reveal {
            index: SLOTS_PER_EPOCH as usize + 5,
        },
        Op::Transition { quorum: 10 },
        Op::RecordBid {
            slot: 7,
            withdrawal: withdrawal(50, 1),
            proposer_index: 5,
        },
        Op::Transition { quorum: 0 },
        Op::Reveal { index: 7 },
        Op::AddWeight {
            index: WINDOW_LEN,
            effective_balance: 1,
        },
    ]);
}
