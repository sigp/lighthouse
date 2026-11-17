-- Hand-written models of the external functions listed in `FunsExternal_Template.lean`.
--
-- Everything in this file is TRUSTED: each definition states what an external Rust function
-- computes, and is not checked against the Rust implementation. The models follow the documented
-- behaviour of `std`.
import Aeneas
import OperationPool.Types
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

open operation_pool

/-! ## `std::collections::HashSet`

The `Eq`, `Hash` and `BuildHasher` instances are ignored: membership is equality of values. -/

/-- The elements of a set. -/
def std.collections.hash.set.HashSet.toList {T : Type} {S : Type} {A : Type}
  (s : std.collections.hash.set.HashSet T S A) : List T := s

/-- The set with the given elements. -/
def std.collections.hash.set.HashSet.ofList {T : Type} {S : Type} {A : Type}
  (l : List T) : std.collections.hash.set.HashSet T S A := l

/-- [std::collections::hash::set::{HashSet<T, RandomState>}::with_capacity]

    The empty set; the capacity is only a hint. -/
@[rust_fun
  "std::collections::hash::set::{std::collections::hash::set::HashSet<@T, std::hash::random::RandomState, alloc::alloc::Global>}::with_capacity"]
def std.collections.hash.set.HashSetTRandomStateGlobal.with_capacity
  (T : Type) (_ : Std.Usize) :
  Result (std.collections.hash.set.HashSet T std.hash.random.RandomState
    alloc.alloc.Global) :=
  ok (std.collections.hash.set.HashSet.ofList [])

open Classical in
/-- [std::collections::hash::set::{HashSet<T, S, A>}::contains]

    Whether some element of the set borrows as the given value. -/
@[rust_fun
  "std::collections::hash::set::{std::collections::hash::set::HashSet<@T, @S, @A>}::contains"]
noncomputable def std.collections.hash.set.HashSet.contains
  {T : Type} {S : Type} {A : Type} {Q : Type} {Clause2_Hasher : Type}
  (corecmpEqInst : core.cmp.Eq T) (corehashHashInst : core.hash.Hash T)
  (corehashBuildHasherInst : core.hash.BuildHasher S Clause2_Hasher)
  (coreborrowBorrowInst : core.borrow.Borrow T Q) (corehashHashInst1 :
  core.hash.Hash Q) (corecmpEqInst1 : core.cmp.Eq Q)
  (s : std.collections.hash.set.HashSet T S A) (value : Q) : Result Bool :=
  ok (decide (∃ t ∈ s.toList, coreborrowBorrowInst.borrow t = ok value))

open Classical in
/-- [std::collections::hash::set::{HashSet<T, S, A>}::insert]

    Adds the value if it is not already present, and returns whether it was added. -/
@[rust_fun
  "std::collections::hash::set::{std::collections::hash::set::HashSet<@T, @S, @A>}::insert"]
noncomputable def std.collections.hash.set.HashSet.insert
  {T : Type} {S : Type} {A : Type} {Clause2_Hasher : Type} (corecmpEqInst :
  core.cmp.Eq T) (corehashHashInst : core.hash.Hash T) (corehashBuildHasherInst
  : core.hash.BuildHasher S Clause2_Hasher)
  (s : std.collections.hash.set.HashSet T S A) (value : T) :
  Result (Bool × (std.collections.hash.set.HashSet T S A)) :=
  if value ∈ s.toList then ok (false, s)
  else ok (true, std.collections.hash.set.HashSet.ofList (value :: s.toList))

/-! The hashing functions below are never called by the extracted code; they only appear as
fields of trait instances. They are left opaque. -/

/-- [core::hash::impls::{impl core::hash::Hash for u64}::hash] -/
@[rust_fun "core::hash::impls::{core::hash::Hash<u64>}::hash"]
axiom U64.Insts.CoreHashHash.hash
  {H : Type} (HasherInst : core.hash.Hasher H) : Std.U64 → H → Result H

/-- [std::hash::random::{impl core::hash::Hasher for DefaultHasher}::finish] -/
@[rust_fun
  "std::hash::random::{core::hash::Hasher<std::hash::random::DefaultHasher>}::finish"]
axiom std.hash.random.DefaultHasher.Insts.CoreHashHasher.finish
  : std.hash.random.DefaultHasher → Result Std.U64

/-- [std::hash::random::{impl core::hash::Hasher for DefaultHasher}::write] -/
@[rust_fun
  "std::hash::random::{core::hash::Hasher<std::hash::random::DefaultHasher>}::write"]
axiom std.hash.random.DefaultHasher.Insts.CoreHashHasher.write
  :
  std.hash.random.DefaultHasher → Slice Std.U8 → Result
    std.hash.random.DefaultHasher

/-- [std::hash::random::{impl core::hash::BuildHasher for RandomState}::build_hasher] -/
@[rust_fun
  "std::hash::random::{core::hash::BuildHasher<std::hash::random::RandomState, std::hash::random::DefaultHasher>}::build_hasher"]
axiom
  std.hash.random.RandomState.Insts.CoreHashBuildHasherDefaultHasher.build_hasher
  : std.hash.random.RandomState → Result std.hash.random.DefaultHasher
