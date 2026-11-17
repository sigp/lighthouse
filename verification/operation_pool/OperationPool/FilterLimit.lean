import OperationPool.Funs

/-!
# `filter_limit_operations` keeps the first `limit` operations that pass the filter

`filter_limit_operations` in `beacon_node/operation_pool/src/lib.rs` walks an iterator, keeps
each operation the filter accepts, maps it, and stops once it holds `limit` results. The op pool
packs proposer slashings, voluntary exits and BLS-to-execution changes through it.

The function is generic over the iterator and over the two closures, so the theorem is too. It
takes an iterator that yields a list `l` (`Yields`), and closures that compute the functions `p`
and `m` on the elements of `l`. The result is then `((l.filter p).take limit).map m`, and the
function does not panic.
-/

open Aeneas Aeneas.Std Result

namespace operation_pool

/-- `Yields inst it l`: calling `next` on `it` again and again returns the elements of `l` in
order, and then `None`. -/
inductive Yields {It Item : Type} (inst : core.iter.traits.iterator.Iterator It Item) :
    It → List Item → Prop
  | done {it it' : It} : inst.next it = ok (none, it') → Yields inst it []
  | step {it it' : It} {x : Item} {xs : List Item} :
      inst.next it = ok (some x, it') → Yields inst it' xs → Yields inst it (x :: xs)

/-- `Vec::push` appends when the vector is not at its maximum length. -/
theorem vec_push_eq {α : Type} (v : alloc.vec.Vec α) (x : α) (h : v.val.length < Usize.max) :
    ∃ v', alloc.vec.Vec.push v x = ok v' ∧ v'.val = v.val ++ [x] := by
  have hcond : (decide (v.val.length + 1 ≤ U32.max) || decide (v.val.length + 1 ≤ Usize.max)) = true := by
    simp only [Bool.or_eq_true, decide_eq_true_eq]
    right
    omega
  refine ⟨alloc.vec.Vec.from (v.val.concat x) (by simp; omega), ?_, by simp⟩
  unfold alloc.vec.Vec.push
  simp only [hcond, _root_.dite_true]

section

variable {T V I F G It : Type}
  (iterInst : core.iter.traits.collect.IntoIterator I T It)
  (filterInst : core.ops.function.Fn F T Bool) (mappingInst : core.ops.function.Fn G T V)
  (filter : F) (mapping : G) (limit : Usize)

/-- The loop of `filter_limit_operations`, started with `selected` already chosen and an iterator
that yields `l`: it appends the first accepted operations of `l`, mapped, until `selected` holds
`limit` elements. -/
theorem filter_limit_operations_loop_eq {it : It} {l : List T}
    (hyields : Yields iterInst.iteratorInst it l)
    (p : T → Bool) (hp : ∀ x ∈ l, filterInst.call filter x = ok (p x))
    (m : T → V) (hm : ∀ x ∈ l, mappingInst.call mapping x = ok (m x))
    (selected : alloc.vec.Vec V) (hselected : selected.length ≤ limit.val) :
    ∃ out, filter_limit_operations_loop iterInst filterInst mappingInst filter mapping limit
        selected it = ok out ∧
      out.val = selected.val ++ ((l.filter p).take (limit.val - selected.length)).map m := by
  induction hyields generalizing selected with
  | done hnext =>
    rw [filter_limit_operations_loop]
    by_cases hlt : alloc.vec.Vec.len selected < limit
    · exact ⟨selected, by simp [hlt, hnext], by simp⟩
    · exact ⟨selected, by simp [hlt], by simp⟩
  | @step it it' x xs hnext _ ih =>
    have hpx := hp x List.mem_cons_self
    have hmx := hm x List.mem_cons_self
    have hp' : ∀ y ∈ xs, filterInst.call filter y = ok (p y) :=
      fun y hy => hp y (List.mem_cons_of_mem _ hy)
    have hm' : ∀ y ∈ xs, mappingInst.call mapping y = ok (m y) :=
      fun y hy => hm y (List.mem_cons_of_mem _ hy)
    rw [filter_limit_operations_loop]
    by_cases hlt : alloc.vec.Vec.len selected < limit
    · have hlen : selected.length < limit.val := by scalar_tac
      cases hkeep : p x with
      | false =>
        obtain ⟨out, hout, hval⟩ := ih hp' hm' selected hselected
        refine ⟨out, ?_, ?_⟩
        · simp [hlt, hnext, hpx, hkeep, hout]
        · simp [hval, hkeep]
      | true =>
        obtain ⟨selected1, hpush, hselected1⟩ := vec_push_eq selected (m x) (by scalar_tac)
        have hlen1 : selected1.length = selected.length + 1 := by
          simp [alloc.vec.Vec.length, hselected1]
        obtain ⟨out, hout, hval⟩ := ih hp' hm' selected1 (by omega)
        refine ⟨out, ?_, ?_⟩
        · simp [hlt, hnext, hpx, hkeep, hmx, hpush, hout]
        · have htake : limit.val - selected.length = (limit.val - selected1.length) + 1 := by omega
          simp [hval, hselected1, hkeep, htake, List.take_succ_cons]
    · have hlen : limit.val - selected.length = 0 := by scalar_tac
      exact ⟨selected, by simp [hlt], by simp [hlen]⟩

/-- `filter_limit_operations` never panics on an iterator that yields `l`, and returns the first
`limit` elements of `l` that pass the filter, mapped.

`p` and `m` are what the two closures compute on the elements of `l`. The `Clone` bound of the
Rust signature is unused. -/
theorem filter_limit_operations_eq (cloneInst : core.clone.Clone T) (operations : I) {it : It}
    {l : List T} (hinto : iterInst.into_iter operations = ok it)
    (hyields : Yields iterInst.iteratorInst it l)
    (p : T → Bool) (hp : ∀ x ∈ l, filterInst.call filter x = ok (p x))
    (m : T → V) (hm : ∀ x ∈ l, mappingInst.call mapping x = ok (m x)) :
    ∃ out, filter_limit_operations iterInst filterInst mappingInst cloneInst operations filter
        mapping limit = ok out ∧
      out.val = ((l.filter p).take limit.val).map m := by
  obtain ⟨out, hout, hval⟩ := filter_limit_operations_loop_eq iterInst filterInst mappingInst
    filter mapping limit hyields p hp m hm (alloc.vec.Vec.new V) (by simp)
  refine ⟨out, ?_, ?_⟩
  · simp [filter_limit_operations, hinto, hout]
  · simpa using hval

end

end operation_pool
