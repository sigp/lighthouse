import OperationPool.Funs

/-!
# The exclusion set covers every validator the packed slashings can slash

`get_slashings_and_exits` in `beacon_node/operation_pool/src/lib.rs` excludes from the packed
voluntary exits every validator index in a set. Two functions add to that set from the packed
slashings alone:

* `insert_proposer_slashing_indices` adds the proposer index of each proposer slashing.
* `insert_common_attesting_indices` adds each index that the two attestations of an attester
  slashing share.

Both only add, so the theorems hold for any initial set. Processing a proposer slashing slashes
its proposer, and processing an attester slashing slashes only validators that both attestations
name, so the resulting set covers every validator those slashings can slash.
-/

open Aeneas Aeneas.Std Result

namespace operation_pool

open types.slashing.proposer_slashing (ProposerSlashing)

/-- A set of validator indices, as the op pool holds it. -/
abbrev IndexSet : Type :=
  std.collections.hash.set.HashSet Std.U64 std.hash.random.RandomState alloc.alloc.Global

/-! ## Library facts -/

/-- `next` on a slice iterator: the element at the cursor, if there is one. -/
theorem slice_iter_next {T : Type} (slice : Slice T) (i : Nat) :
    core.slice.iter.IteratorSliceIter.next ⟨slice, i⟩ =
      match slice.val[i]? with
      | some x => ok (some x, ⟨slice, i + 1⟩)
      | none => ok (none, ⟨slice, i⟩) := by
  unfold core.slice.iter.IteratorSliceIter.next
  by_cases h : i < slice.val.length
  · simp [h]
    rfl
  · simp [h]

/-- Inserting into a set adds exactly that index. -/
theorem index_set_insert (s : IndexSet) (v : U64) :
    ∃ b s', std.collections.hash.set.HashSet.insert core.cmp.EqU64 U64.Insts.CoreHashHash
        std.hash.random.RandomState.Insts.CoreHashBuildHasherDefaultHasher s v = ok (b, s') ∧
      ∀ i, i ∈ s'.toList ↔ i = v ∨ i ∈ s.toList := by
  unfold std.collections.hash.set.HashSet.insert
  by_cases h : v ∈ s.toList
  · refine ⟨false, s, by simp [h], ?_⟩
    intro i
    constructor
    · intro hi; exact Or.inr hi
    · rintro (rfl | hi)
      · exact h
      · exact hi
  · refine ⟨true, std.collections.hash.set.HashSet.ofList (v :: s.toList), by simp [h], ?_⟩
    intro i
    exact List.mem_cons

/-- `contains` is membership. -/
theorem index_set_contains (s : IndexSet) (v : U64) :
    ∃ b, std.collections.hash.set.HashSet.contains core.cmp.EqU64 U64.Insts.CoreHashHash
        std.hash.random.RandomState.Insts.CoreHashBuildHasherDefaultHasher
        (core.borrow.Borrow.Blanket Std.U64) U64.Insts.CoreHashHash core.cmp.EqU64 s v = ok b ∧
      (b = true ↔ v ∈ s.toList) := by
  unfold std.collections.hash.set.HashSet.contains
  refine ⟨_, rfl, ?_⟩
  simp [core.borrow.Borrow.Blanket.borrow]

/-! ## Proposer slashings -/

/-- The loop adds the proposer index of every slashing from position `i` on. -/
theorem insert_proposer_slashing_indices_loop_eq (slice : Slice ProposerSlashing) :
    ∀ (n i : Nat) (s : IndexSet), slice.val.length - i = n →
      ∃ s', insert_proposer_slashing_indices_loop ⟨slice, i⟩ s = ok s' ∧
        ∀ x, x ∈ s'.toList ↔ x ∈ s.toList ∨
          ∃ slashing ∈ slice.val.drop i, slashing.signed_header_1.message.proposer_index = x := by
  intro n
  induction n with
  | zero =>
    intro i s hn
    have hnone : slice.val[i]? = none := List.getElem?_eq_none (by omega)
    refine ⟨s, ?_, ?_⟩
    · rw [insert_proposer_slashing_indices_loop, slice_iter_next, hnone]
      simp
    · intro x
      simp [List.drop_eq_nil_of_le (show slice.val.length ≤ i by omega)]
  | succ n ih =>
    intro i s hn
    have hi : i < slice.val.length := by omega
    have hsome : slice.val[i]? = some slice.val[i] := List.getElem?_eq_getElem hi
    obtain ⟨b, s1, hins, hs1⟩ :=
      index_set_insert s slice.val[i].signed_header_1.message.proposer_index
    obtain ⟨s', hs', hmem⟩ := ih (i + 1) s1 (by omega)
    refine ⟨s', ?_, ?_⟩
    · rw [insert_proposer_slashing_indices_loop, slice_iter_next, hsome]
      simp [hins, hs']
    · intro x
      rw [hmem, hs1, List.drop_eq_getElem_cons hi]
      simp only [List.mem_cons, exists_eq_or_imp]
      constructor
      · rintro ((rfl | hx) | hx)
        · exact Or.inr (Or.inl rfl)
        · exact Or.inl hx
        · exact Or.inr (Or.inr hx)
      · rintro (hx | hx | hx)
        · exact Or.inl (Or.inr hx)
        · exact Or.inl (Or.inl hx.symm)
        · exact Or.inr hx

/-- `insert_proposer_slashing_indices` never panics, and adds exactly the proposer index of each
slashing. -/
theorem insert_proposer_slashing_indices_eq (s : IndexSet) (slashings : Slice ProposerSlashing) :
    ∃ s', insert_proposer_slashing_indices s slashings = ok s' ∧
      ∀ i, i ∈ s'.toList ↔ i ∈ s.toList ∨
        ∃ slashing ∈ slashings.val, slashing.signed_header_1.message.proposer_index = i := by
  obtain ⟨s', hs', hmem⟩ :=
    insert_proposer_slashing_indices_loop_eq slashings slashings.val.length 0 s rfl
  refine ⟨s', ?_, by simpa using hmem⟩
  simp [insert_proposer_slashing_indices,
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, hs']

/-! ## Attester slashings -/

/-- The first loop collects the indices of `slice` from position `i` on. -/
theorem insert_common_attesting_indices_loop0_eq (slice : Slice U64) :
    ∀ (n i : Nat) (s : IndexSet), slice.val.length - i = n →
      ∃ s', insert_common_attesting_indices_loop0 ⟨slice, i⟩ s = ok s' ∧
        ∀ x, x ∈ s'.toList ↔ x ∈ s.toList ∨ x ∈ slice.val.drop i := by
  intro n
  induction n with
  | zero =>
    intro i s hn
    have hnone : slice.val[i]? = none := List.getElem?_eq_none (by omega)
    refine ⟨s, ?_, ?_⟩
    · rw [insert_common_attesting_indices_loop0, slice_iter_next, hnone]
      simp
    · intro x
      simp [List.drop_eq_nil_of_le (show slice.val.length ≤ i by omega)]
  | succ n ih =>
    intro i s hn
    have hi : i < slice.val.length := by omega
    have hsome : slice.val[i]? = some slice.val[i] := List.getElem?_eq_getElem hi
    obtain ⟨b, s1, hins, hs1⟩ := index_set_insert s slice.val[i]
    obtain ⟨s', hs', hmem⟩ := ih (i + 1) s1 (by omega)
    refine ⟨s', ?_, ?_⟩
    · rw [insert_common_attesting_indices_loop0, slice_iter_next, hsome]
      simp [hins, hs']
    · intro x
      rw [hmem, hs1, List.drop_eq_getElem_cons hi]
      simp only [List.mem_cons]
      constructor
      · rintro ((hx | hx) | hx)
        · exact Or.inr (Or.inl hx)
        · exact Or.inl hx
        · exact Or.inr (Or.inr hx)
      · rintro (hx | hx | hx)
        · exact Or.inl (Or.inr hx)
        · exact Or.inl (Or.inl hx)
        · exact Or.inr hx

/-- The second loop adds each index of `slice`, from position `i` on, that is in `inFirst`. -/
theorem insert_common_attesting_indices_loop1_eq (slice : Slice U64) (inFirst : IndexSet) :
    ∀ (n i : Nat) (s : IndexSet), slice.val.length - i = n →
      ∃ s', insert_common_attesting_indices_loop1 ⟨slice, i⟩ s inFirst = ok s' ∧
        ∀ x, x ∈ s'.toList ↔ x ∈ s.toList ∨ (x ∈ slice.val.drop i ∧ x ∈ inFirst.toList) := by
  intro n
  induction n with
  | zero =>
    intro i s hn
    have hnone : slice.val[i]? = none := List.getElem?_eq_none (by omega)
    refine ⟨s, ?_, ?_⟩
    · rw [insert_common_attesting_indices_loop1, slice_iter_next, hnone]
      simp
    · intro x
      simp [List.drop_eq_nil_of_le (show slice.val.length ≤ i by omega)]
  | succ n ih =>
    intro i s hn
    have hi : i < slice.val.length := by omega
    have hsome : slice.val[i]? = some slice.val[i] := List.getElem?_eq_getElem hi
    obtain ⟨b, hcontains, hb⟩ := index_set_contains inFirst slice.val[i]
    cases b with
    | false =>
      have hnot : slice.val[i] ∉ inFirst.toList := fun h => by simpa using hb.mpr h
      obtain ⟨s', hs', hmem⟩ := ih (i + 1) s (by omega)
      refine ⟨s', ?_, ?_⟩
      · rw [insert_common_attesting_indices_loop1, slice_iter_next, hsome]
        simp [hcontains, hs']
      · intro x
        rw [hmem, List.drop_eq_getElem_cons hi]
        simp only [List.mem_cons]
        constructor
        · rintro (hx | ⟨hx, hin⟩)
          · exact Or.inl hx
          · exact Or.inr ⟨Or.inr hx, hin⟩
        · rintro (hx | ⟨hx | hx, hin⟩)
          · exact Or.inl hx
          · exact absurd (hx ▸ hin) hnot
          · exact Or.inr ⟨hx, hin⟩
    | true =>
      have hin : slice.val[i] ∈ inFirst.toList := hb.mp rfl
      obtain ⟨b', s1, hins, hs1⟩ := index_set_insert s slice.val[i]
      obtain ⟨s', hs', hmem⟩ := ih (i + 1) s1 (by omega)
      refine ⟨s', ?_, ?_⟩
      · rw [insert_common_attesting_indices_loop1, slice_iter_next, hsome]
        simp [hcontains, hins, hs']
      · intro x
        rw [hmem, hs1, List.drop_eq_getElem_cons hi]
        simp only [List.mem_cons]
        constructor
        · rintro ((hx | hx) | ⟨hx, hxin⟩)
          · exact Or.inr ⟨Or.inl hx, hx ▸ hin⟩
          · exact Or.inl hx
          · exact Or.inr ⟨Or.inr hx, hxin⟩
        · rintro (hx | ⟨hx | hx, hxin⟩)
          · exact Or.inl (Or.inr hx)
          · exact Or.inl (Or.inl hx)
          · exact Or.inr ⟨hx, hxin⟩

/-- `insert_common_attesting_indices` never panics, and adds exactly the indices that occur in
both slices. -/
theorem insert_common_attesting_indices_eq (s : IndexSet) (first second : Slice U64) :
    ∃ s', insert_common_attesting_indices s first second = ok s' ∧
      ∀ i, i ∈ s'.toList ↔ i ∈ s.toList ∨ (i ∈ first.val ∧ i ∈ second.val) := by
  obtain ⟨inFirst, hfirst, hinFirst⟩ :=
    insert_common_attesting_indices_loop0_eq first first.val.length 0
      (std.collections.hash.set.HashSet.ofList []) rfl
  obtain ⟨s', hs', hmem⟩ :=
    insert_common_attesting_indices_loop1_eq second inFirst second.val.length 0 s rfl
  refine ⟨s', ?_, ?_⟩
  · simp [insert_common_attesting_indices,
      std.collections.hash.set.HashSetTRandomStateGlobal.with_capacity,
      SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, hfirst, hs']
  · intro i
    rw [hmem, hinFirst]
    simp [std.collections.hash.set.HashSet.toList, std.collections.hash.set.HashSet.ofList,
      and_comm]

/-! ## The set `get_slashings_and_exits` builds -/

/-- The exclusion set as `get_slashings_and_exits` extends it: the proposer indices of the packed
proposer slashings, then the common attesting indices of each packed attester slashing.

This definition mirrors the call site, which is generic over `EthSpec` and is not extracted.
`attesterIndices` holds, for each packed attester slashing, the attesting indices of its two
attestations. -/
noncomputable def exclusionSet (initial : IndexSet) (proposerSlashings : Slice ProposerSlashing)
    (attesterIndices : List (Slice U64 × Slice U64)) : Result IndexSet := do
  let withProposers ← insert_proposer_slashing_indices initial proposerSlashings
  attesterIndices.foldlM (fun s p => insert_common_attesting_indices s p.1 p.2) withProposers

/-- The fold over the attester slashings keeps what the set holds, and adds the common indices of
every pair. -/
theorem insert_common_attesting_indices_foldlM :
    ∀ (pairs : List (Slice U64 × Slice U64)) (s : IndexSet),
      ∃ s', pairs.foldlM (fun s p => insert_common_attesting_indices s p.1 p.2) s = ok s' ∧
        (∀ i ∈ s.toList, i ∈ s'.toList) ∧
        ∀ p ∈ pairs, ∀ i, i ∈ p.1.val → i ∈ p.2.val → i ∈ s'.toList
  | [], s => ⟨s, by rw [List.foldlM_nil]; rfl, fun _ h => h, fun _ h => nomatch h⟩
  | p :: rest, s => by
    obtain ⟨s1, hs1, hmem1⟩ := insert_common_attesting_indices_eq s p.1 p.2
    obtain ⟨s', hs', hkeep, hrest⟩ := insert_common_attesting_indices_foldlM rest s1
    refine ⟨s', by simp [List.foldlM_cons, hs1, hs'], ?_, ?_⟩
    · exact fun i hi => hkeep i ((hmem1 i).mpr (Or.inl hi))
    · intro q hq i hi1 hi2
      rcases List.mem_cons.mp hq with rfl | hq
      · exact hkeep i ((hmem1 i).mpr (Or.inr ⟨hi1, hi2⟩))
      · exact hrest q hq i hi1 hi2

/-- The exclusion set covers every validator the packed slashings can slash: it holds the
proposer index of each proposer slashing, and each index that the two attestations of an
attester slashing share. It also keeps the indices it started with. -/
theorem exclusionSet_covers {initial excl : IndexSet} {proposerSlashings : Slice ProposerSlashing}
    {attesterIndices : List (Slice U64 × Slice U64)}
    (h : exclusionSet initial proposerSlashings attesterIndices = ok excl) :
    (∀ i ∈ initial.toList, i ∈ excl.toList) ∧
    (∀ slashing ∈ proposerSlashings.val,
      slashing.signed_header_1.message.proposer_index ∈ excl.toList) ∧
    ∀ p ∈ attesterIndices, ∀ i, i ∈ p.1.val → i ∈ p.2.val → i ∈ excl.toList := by
  obtain ⟨s1, hs1, hmem1⟩ := insert_proposer_slashing_indices_eq initial proposerSlashings
  obtain ⟨s', hs', hkeep, hpairs⟩ := insert_common_attesting_indices_foldlM attesterIndices s1
  have hexcl : excl = s' := by
    simp [exclusionSet, hs1, hs'] at h
    exact h.symm
  subst hexcl
  refine ⟨fun i hi => hkeep i ((hmem1 i).mpr (Or.inl hi)), fun slashing hsl => ?_, hpairs⟩
  exact hkeep _ ((hmem1 _).mpr (Or.inr ⟨slashing, hsl, rfl⟩))

end operation_pool
