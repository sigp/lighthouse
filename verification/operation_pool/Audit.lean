import OperationPool
import StateProcessing

/-!
# Axiom audit

`./lake.sh build Audit` prints the axioms each main theorem depends on. Expected:

* Lean's `propext`, `Classical.choice` and `Quot.sound`;
* opaque declarations of `ExternalTypes.lean`, `TypesExternal.lean` and `FunsExternal.lean`.
  These are external Rust types, and hashing functions that the extracted code never calls.
  They appear because the extracted signatures mention them. Each is an uninterpreted symbol:
  it asserts that a type or a function exists, and nothing about it.

`sorryAx` must not appear.
-/

#print axioms OperationPool.packed_exits_valid_after_slashings_uniform
#print axioms OperationPool.packed_exits_valid_after_slashings
#print axioms OperationPool.packed_exits_valid
#print axioms OperationPool.packed_exits_valid_direct
#print axioms operation_pool.exclusionSet_covers
#print axioms OperationPool.Bridge.exitGates_of_coresOk
#print axioms OperationPool.Bridge.mem_qsort
#print axioms EthCLSpecs.Proofs.Fulu.exitView_of_slashings
#print axioms EthCLSpecs.Proofs.Fulu.processVoluntaryExit_succeeds
#print axioms operation_pool.filter_limit_operations_eq
#print axioms operation_pool.insert_proposer_slashing_indices_eq
#print axioms operation_pool.insert_common_attesting_indices_eq
#print axioms state_processing.verify_exit_validator_checks_ok_iff
#print axioms state_processing.verify_exit_pending_balance_ok_iff
#print axioms EthCLSpecs.Proofs.Fulu.voluntaryExits_succeed_of_exitView
