import Batteries.Tactic.OpenPrivate

/-!
# `Array.qsort` returns a permutation of its input

The spec sorts the validator indices that `process_attester_slashing` walks with `Array.qsort`.
Core Lean defines `qsort` and states no lemma about it. The bridge needs one fact: an element of
the sorted array is an element of the input. `Array.qsort` only swaps entries, so its result is a
permutation of its input, and membership carries over.

The two helper functions of the core definition are private. `open private` makes them
nameable.
-/

open private Array.qpartition.loop Array.qsort.sort from Init.Data.Array.QSort.Basic

namespace OperationPool.Bridge

variable {α : Type}

/-- The partition loop only swaps: the vector it returns is a permutation of the one it is
handed. The induction is on `hi - k`, the number of entries the loop has left to examine. -/
theorem qpartition_loop_perm {n : Nat} (lt : α → α → Bool) (lo hi : Nat) (hhi : hi < n)
    (pivot : α) :
    ∀ (m : Nat) (as : Vector α n) (i k : Nat) (ilo : lo ≤ i) (ik : i ≤ k) (w : k ≤ hi),
      hi - k = m → (Array.qpartition.loop lt lo hi hhi pivot as i k ilo ik w).2.Perm as := by
  intro m
  induction m with
  | zero =>
    intro as i k ilo ik w hm
    unfold Array.qpartition.loop
    have hk : ¬ k < hi := by omega
    simp only [hk, ↓reduceDIte]
    exact Vector.swap_perm (by omega) (by omega)
  | succ m ih =>
    intro as i k ilo ik w hm
    unfold Array.qpartition.loop
    have hk : k < hi := by omega
    simp only [hk, ↓reduceDIte]
    split
    · exact (ih _ _ _ _ _ _ (by omega)).trans (Vector.swap_perm (by omega) (by omega))
    · exact ih _ _ _ _ _ _ (by omega)

/-- A conditional swap gives a permutation. -/
theorem ite_swap_perm {n : Nat} (c : Prop) [Decidable c] (xs : Vector α n) (i j : Nat)
    (hi : i < n) (hj : j < n) : (if c then xs.swap i j hi hj else xs).Perm xs := by
  split
  · exact Vector.swap_perm hi hj
  · exact Vector.Perm.refl _

/-- `qpartition` returns a permutation: it moves the pivot with three conditional swaps, and then
runs the loop. -/
theorem qpartition_perm {n : Nat} (as : Vector α n) (lt : α → α → Bool) (lo hi : Nat)
    (w : lo ≤ hi) (hlo : lo < n) (hhi : hi < n) :
    (Array.qpartition as lt lo hi w hlo hhi).2.Perm as := by
  unfold Array.qpartition
  dsimp only
  refine (qpartition_loop_perm lt lo hi hhi _ _ _ _ _ _ _ _ rfl).trans ?_
  exact (ite_swap_perm _ _ _ _ _ _).trans
    ((ite_swap_perm _ _ _ _ _ _).trans (ite_swap_perm _ _ _ _ _ _))

/-- The recursive sort returns a permutation. The induction is on a bound for `hi - lo`, which
both recursive calls decrease. -/
theorem qsort_sort_perm (lt : α → α → Bool) {n : Nat} :
    ∀ (m : Nat) (as : Vector α n) (lo hi : Nat) (w : lo ≤ hi) (hlo : lo < n) (hhi : hi < n),
      hi - lo ≤ m → (Array.qsort.sort lt as lo hi w hlo hhi).Perm as := by
  intro m
  induction m with
  | zero =>
    intro as lo hi w hlo hhi hm
    unfold Array.qsort.sort
    have h₁ : ¬ lo < hi := by omega
    simp only [h₁, ↓reduceDIte]
    exact Vector.Perm.refl _
  | succ m ih =>
    intro as lo hi w hlo hhi hm
    unfold Array.qsort.sort
    by_cases h₁ : lo < hi
    · simp only [h₁, ↓reduceDIte]
      have hpart := qpartition_perm as lt lo hi w hlo hhi
      generalize Array.qpartition as lt lo hi w hlo hhi = q at hpart ⊢
      obtain ⟨⟨mid, hmid⟩, as'⟩ := q
      dsimp only at hpart ⊢
      split
      · exact hpart
      · exact ((ih _ _ _ _ _ _ (by omega)).trans (ih _ _ _ _ _ _ (by omega))).trans hpart
    · simp only [h₁, ↓reduceDIte]
      exact Vector.Perm.refl _

/-- `Array.qsort` returns a permutation of its input. -/
theorem qsort_perm (as : Array α) (lt : α → α → Bool) (lo hi : Nat) :
    (as.qsort lt lo hi).Perm as := by
  unfold Array.qsort
  split
  · exact Array.Perm.refl _
  · exact (qsort_sort_perm lt _ as.toVector _ _ _ _ _ (Nat.le_refl _)).toArray

/-- An element of a sorted array is an element of the input. -/
theorem mem_qsort {as : Array α} {lt : α → α → Bool} {lo hi : Nat} {a : α} :
    a ∈ as.qsort lt lo hi ↔ a ∈ as :=
  (qsort_perm as lt lo hi).mem_iff

end OperationPool.Bridge
