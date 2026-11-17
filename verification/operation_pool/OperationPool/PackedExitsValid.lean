import OperationPool.FilterLimit
import OperationPool.ExclusionSet
import OperationPool.Bridge.QSort
import OperationPool.Bridge.StateCorr
import EthCLSpecs.Proofs.Fulu.VoluntaryExits.Slashings

/-!
# The packed voluntary exits are valid

The main theorem of this project. `OperationPool::get_voluntary_exits` packs voluntary exits
with `filter_limit_operations`. `packed_exits_valid` states that the spec processes the packed
exits, in order, without an error.

The theorem joins three proofs:

* `filter_limit_operations_eq` (extracted Rust): the packed exits are the first `limit` pool
  entries that the filter closure accepts.
* `exitGates_of_coresOk` (extracted Rust to spec): an exit that the cores of `verify_exit`
  accept passes the spec's `ExitGates`.
* `voluntaryExits_succeed_of_exitView` (spec, in Etheorem): exits that name distinct validators
  and pass the gates are processed in order without an error.

`packed_exits_valid_after_slashings` adds the slashings of the block. `get_slashings_and_exits`
excludes from the exits every validator in a set, and `exclusionSet_covers` (extracted Rust)
proves that the set holds every validator the packed slashings can slash.
`exitView_of_slashings` (spec) then gives the exit view of the state after the slashings.
`packed_exits_valid_after_slashings_uniform` states the result with one bound on the exit queue.

The hypotheses that are not proved from extracted code are the trusted base. `README.md` lists
them.
-/

namespace OperationPool

open EthCLLib.Spec (HasherTag CryptoBackend)
open EthCLLib.Proofs (runPure)
open EthCLSpecs.Fulu
open EthCLSpecs.Proofs.Fulu
open OperationPool.Bridge

section

variable [Preset] [Config] [HasherTag] [CryptoBackend] [PresetValid] [ConfigValid]

variable {Op X I F G It : Type}
  (iterInst : Aeneas.Std.core.iter.traits.collect.IntoIterator I Op It)
  (filterInst : Aeneas.Std.core.ops.function.Fn F Op Bool)
  (mappingInst : Aeneas.Std.core.ops.function.Fn G Op X)
  (cloneInst : Aeneas.Std.core.clone.Clone Op)
  (operations : I) (filter : F) (mapping : G) (limit : Aeneas.Std.Usize)

/-- The voluntary exits that `filter_limit_operations` packs are processed by the spec without
an error, in order, from any state `w` that has the exit view of the packing state `s`.

The Rust side:

* `Op` is a pool entry and `X` a packed exit. `pool` is what the pool's iterator yields.
* `keep` and `exitOf` are what the filter and mapping closures compute.
* `message` reads the Rust `VoluntaryExit` of a packed exit, and `toSpec` gives the spec's form
  of the exit, with the same validator index and epoch.
* `hkeys`: the pool entries name pairwise distinct validators.
* `hkeep`: the filter accepts an entry only when its validator is outside `S`, both cores of
  `verify_exit` accept it on `view`, and its signature is valid.

The spec side:

* `hcorr`: the state Lighthouse reads corresponds to the spec state `s`.
* `hview`: `w` is the state the exits run from. `S` holds the validators that the steps between
  `s` and `w` may have changed.

The conclusion: `filter_limit_operations` does not panic, it packs at most `limit` exits, and
when the exit queue has room for them the spec's fold over the packed exits succeeds. -/
theorem packed_exits_valid {it : It} {pool : List Op}
    (hinto : iterInst.into_iter operations = Aeneas.Std.Result.ok it)
    (hyields : operation_pool.Yields iterInst.iteratorInst it pool)
    (keep : Op → Bool)
    (hfilter : ∀ op ∈ pool, filterInst.call filter op = Aeneas.Std.Result.ok (keep op))
    (exitOf : Op → X)
    (hmapping : ∀ op ∈ pool, mappingInst.call mapping op = Aeneas.Std.Result.ok (exitOf op))
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hmessage : ∀ op ∈ pool,
      (toSpec (exitOf op)).message.validatorIndex = u64ToSpec (message (exitOf op)).validator_index ∧
      (toSpec (exitOf op)).message.epoch = u64ToSpec (message (exitOf op)).epoch)
    (hkeys : pool.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index)
    {view : StateView} {s w : BeaconState} (hcorr : StateCorr view s)
    {S : ValidatorIndex → Prop} (hview : ExitView S s w)
    (hkeep : ∀ op ∈ pool, keep op = true →
      ¬ S (toSpec (exitOf op)).message.validatorIndex ∧
      CoresOk view (message (exitOf op)) ∧
      ExitSigned s (toSpec (exitOf op))) :
    ∃ out, operation_pool.filter_limit_operations iterInst filterInst mappingInst cloneInst
        operations filter mapping limit = Aeneas.Std.Result.ok out ∧
      out.val.length ≤ limit.val ∧
      (ExitRoomAt (exitStart w) s (out.val.map toSpec) →
        ∃ w', runPure (processVoluntaryExits (out.val.map toSpec).toArray) w = .ok ((), w')) := by
  obtain ⟨out, hout, hval⟩ := operation_pool.filter_limit_operations_eq iterInst filterInst
    mappingInst filter mapping limit cloneInst operations hinto hyields keep hfilter exitOf
    hmapping
  refine ⟨out, hout, ?_, ?_⟩
  · rw [hval, List.length_map]
    exact List.length_take_le _ _
  · intro hroom
    -- The packed pool entries: a sublist of the pool, all accepted by the filter.
    have hsub : ((pool.filter keep).take limit.val).Sublist pool :=
      (List.take_sublist _ _).trans List.filter_sublist
    have hmem : ∀ op ∈ (pool.filter keep).take limit.val, op ∈ pool ∧ keep op = true :=
      fun op hop => List.mem_filter.mp (List.mem_of_mem_take hop)
    have hexits : out.val.map toSpec =
        ((pool.filter keep).take limit.val).map (fun op => toSpec (exitOf op)) := by
      rw [hval, List.map_map]
      rfl
    rw [hexits] at hroom ⊢
    refine voluntaryExits_succeed_of_exitView _ hview ?_ ?_ ?_ ?_ (by simpa using hroom)
    · -- Distinct Rust indices give distinct spec indices.
      simp only [List.pairwise_map]
      refine (hkeys.sublist hsub).imp_of_mem ?_
      intro a b ha hb hne heq
      refine hne (u64ToSpec_inj ?_)
      rw [← (hmessage a (hmem a ha).1).1, ← (hmessage b (hmem b hb).1).1]
      exact heq
    · intro sve hsve
      obtain ⟨op, hop, rfl⟩ := List.mem_map.mp (List.mem_toArray.mp hsve)
      obtain ⟨hpool, hk⟩ := hmem op hop
      exact exitGates_of_coresOk hcorr (hmessage op hpool).1 (hmessage op hpool).2
        (hkeep op hpool hk).2.1
    · intro sve hsve
      obtain ⟨op, hop, rfl⟩ := List.mem_map.mp (List.mem_toArray.mp hsve)
      obtain ⟨hpool, hk⟩ := hmem op hop
      exact (hkeep op hpool hk).2.2
    · intro sve hsve
      obtain ⟨op, hop, rfl⟩ := List.mem_map.mp (List.mem_toArray.mp hsve)
      obtain ⟨hpool, hk⟩ := hmem op hop
      exact (hkeep op hpool hk).1

/-- `packed_exits_valid` for exits that run from the packing state itself: no step between
packing and the exits changes a validator. -/
theorem packed_exits_valid_direct {it : It} {pool : List Op}
    (hinto : iterInst.into_iter operations = Aeneas.Std.Result.ok it)
    (hyields : operation_pool.Yields iterInst.iteratorInst it pool)
    (keep : Op → Bool)
    (hfilter : ∀ op ∈ pool, filterInst.call filter op = Aeneas.Std.Result.ok (keep op))
    (exitOf : Op → X)
    (hmapping : ∀ op ∈ pool, mappingInst.call mapping op = Aeneas.Std.Result.ok (exitOf op))
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hmessage : ∀ op ∈ pool,
      (toSpec (exitOf op)).message.validatorIndex = u64ToSpec (message (exitOf op)).validator_index ∧
      (toSpec (exitOf op)).message.epoch = u64ToSpec (message (exitOf op)).epoch)
    (hkeys : pool.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index)
    {view : StateView} {s : BeaconState} (hcorr : StateCorr view s)
    (hkeep : ∀ op ∈ pool, keep op = true →
      CoresOk view (message (exitOf op)) ∧ ExitSigned s (toSpec (exitOf op))) :
    ∃ out, operation_pool.filter_limit_operations iterInst filterInst mappingInst cloneInst
        operations filter mapping limit = Aeneas.Std.Result.ok out ∧
      out.val.length ≤ limit.val ∧
      (ExitRoomAt (exitStart s) s (out.val.map toSpec) →
        ∃ s', runPure (processVoluntaryExits (out.val.map toSpec).toArray) s = .ok ((), s')) :=
  packed_exits_valid iterInst filterInst mappingInst cloneInst operations filter mapping limit
    hinto hyields keep hfilter exitOf hmapping message toSpec hmessage hkeys hcorr
    (ExitView.refl (fun _ => False) s)
    (fun op hop hk => ⟨fun h => h, hkeep op hop hk⟩)

omit [Config] [HasherTag] [CryptoBackend] [PresetValid] [ConfigValid] in
/-- An index `process_attester_slashing` walks is named by both attestations of the slashing:
the walked array is the sorted intersection of the two index lists. -/
theorem mem_attesterSlashingIndices {asl : AttesterSlashing} {i : ValidatorIndex}
    (h : i ∈ attesterSlashingIndices asl) :
    i ∈ asl.attestation1.attestingIndices.toArray ∧
      i ∈ asl.attestation2.attestingIndices.toArray := by
  unfold attesterSlashingIndices at h
  rw [mem_qsort] at h
  unfold EthCLLib.Spec.arrayInter at h
  rw [Array.mem_filter] at h
  exact ⟨h.1, by simpa using h.2⟩

/-- The packed voluntary exits are processed by the spec without an error after the packed
proposer and attester slashings of the same block.

On top of the hypotheses of `packed_exits_valid`:

* `hexcl`: `excl` is the exclusion set that `get_slashings_and_exits` builds from the packed
  slashings. `rustProposerSlashings` and `rustAttesterIndices` are the Rust data it is built
  from.
* `hproposers`, `hattesters`: the spec's slashings carry the same proposer indices and
  attesting indices as the Rust data.
* `hslash₁`, `hslash₂`: the spec processes the proposer slashings and then the attester
  slashings from the packing state `s`, and reaches `s₂`.
* `hkeep`: the filter accepts a pool entry only when its validator is outside `excl`, both
  cores of `verify_exit` accept it, and its signature is valid.

The exits run from `s₂`. -/
theorem packed_exits_valid_after_slashings {it : It} {pool : List Op}
    (hinto : iterInst.into_iter operations = Aeneas.Std.Result.ok it)
    (hyields : operation_pool.Yields iterInst.iteratorInst it pool)
    (keep : Op → Bool)
    (hfilter : ∀ op ∈ pool, filterInst.call filter op = Aeneas.Std.Result.ok (keep op))
    (exitOf : Op → X)
    (hmapping : ∀ op ∈ pool, mappingInst.call mapping op = Aeneas.Std.Result.ok (exitOf op))
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hmessage : ∀ op ∈ pool,
      (toSpec (exitOf op)).message.validatorIndex = u64ToSpec (message (exitOf op)).validator_index ∧
      (toSpec (exitOf op)).message.epoch = u64ToSpec (message (exitOf op)).epoch)
    (hkeys : pool.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index)
    {view : StateView} {s s₁ s₂ : BeaconState} (hcorr : StateCorr view s)
    {initial excl : operation_pool.IndexSet}
    {rustProposerSlashings :
      Aeneas.Std.Slice operation_pool.types.slashing.proposer_slashing.ProposerSlashing}
    {rustAttesterIndices : List (Aeneas.Std.Slice Aeneas.Std.U64 × Aeneas.Std.Slice Aeneas.Std.U64)}
    (hexcl : operation_pool.exclusionSet initial rustProposerSlashings rustAttesterIndices =
      Aeneas.Std.Result.ok excl)
    (proposerSlashings : Array ProposerSlashing) (attesterSlashings : Array AttesterSlashing)
    (hproposers : ∀ ps ∈ proposerSlashings, ∃ r ∈ rustProposerSlashings.val,
      u64ToSpec r.signed_header_1.message.proposer_index = ps.signedHeader1.message.proposerIndex)
    (hattesters : ∀ asl ∈ attesterSlashings, ∃ p ∈ rustAttesterIndices,
      asl.attestation1.attestingIndices.toArray.toList = p.1.val.map u64ToSpec ∧
      asl.attestation2.attestingIndices.toArray.toList = p.2.val.map u64ToSpec)
    (hslash₁ : runPure (ForM.forM proposerSlashings
      (processProposerSlashing (StateTransition := FuluRun))) s = .ok ((), s₁))
    (hslash₂ : runPure (ForM.forM attesterSlashings
      (processAttesterSlashing (StateTransition := FuluRun))) s₁ = .ok ((), s₂))
    (hkeep : ∀ op ∈ pool, keep op = true →
      (message (exitOf op)).validator_index ∉ excl.toList ∧
      CoresOk view (message (exitOf op)) ∧
      ExitSigned s (toSpec (exitOf op))) :
    ∃ out, operation_pool.filter_limit_operations iterInst filterInst mappingInst cloneInst
        operations filter mapping limit = Aeneas.Std.Result.ok out ∧
      out.val.length ≤ limit.val ∧
      (ExitRoomAt (exitStart s₂) s (out.val.map toSpec) →
        ∃ s₃, runPure (processVoluntaryExits (out.val.map toSpec).toArray) s₂ = .ok ((), s₃)) := by
  obtain ⟨_, hcovP, hcovA⟩ := operation_pool.exclusionSet_covers hexcl
  -- The spec validators that the Rust exclusion set holds.
  have hview : ExitView (fun i => ∃ x ∈ excl.toList, u64ToSpec x = i) s s₂ := by
    refine exitView_of_slashings proposerSlashings attesterSlashings (fun ps hps => ?_)
      (fun asl hasl i hi => ?_) hslash₁ hslash₂
    · obtain ⟨r, hr, heq⟩ := hproposers ps hps
      exact ⟨_, hcovP r hr, heq⟩
    · obtain ⟨h1, h2⟩ := mem_attesterSlashingIndices hi
      obtain ⟨p, hp, hl1, hl2⟩ := hattesters asl hasl
      have h1' : i ∈ p.1.val.map u64ToSpec := hl1 ▸ Array.mem_toList_iff.mpr h1
      have h2' : i ∈ p.2.val.map u64ToSpec := hl2 ▸ Array.mem_toList_iff.mpr h2
      obtain ⟨x, hx, rfl⟩ := List.mem_map.mp h1'
      obtain ⟨y, hy, hxy⟩ := List.mem_map.mp h2'
      have hyx : y = x := u64ToSpec_inj hxy
      subst hyx
      exact ⟨y, hcovA p hp y hx hy, rfl⟩
  refine packed_exits_valid iterInst filterInst mappingInst cloneInst operations filter mapping
    limit hinto hyields keep hfilter exitOf hmapping message toSpec hmessage hkeys hcorr hview
    (fun op hop hk => ?_)
  obtain ⟨hnot, hcores, hsig⟩ := hkeep op hop hk
  refine ⟨?_, hcores, hsig⟩
  rintro ⟨x, hx, hxeq⟩
  have hxidx : x = (message (exitOf op)).validator_index :=
    u64ToSpec_inj (hxeq.trans (hmessage op hop).1)
  exact hnot (hxidx ▸ hx)

/-- `packed_exits_valid_after_slashings` with one bound on the exit queue: when the queue has
room for `limit` exits of any balance after the slashings, the packed exits succeed.

`exitStep (2 ^ 64 - 1)` bounds the epochs one exit can take. On mainnet it is about `1.4e8`, and
`limit` is 16, so the bound holds when `exitStart s₂` is at least about `2.3e9` epochs below
`2 ^ 64`. -/
theorem packed_exits_valid_after_slashings_uniform {it : It} {pool : List Op}
    (hinto : iterInst.into_iter operations = Aeneas.Std.Result.ok it)
    (hyields : operation_pool.Yields iterInst.iteratorInst it pool)
    (keep : Op → Bool)
    (hfilter : ∀ op ∈ pool, filterInst.call filter op = Aeneas.Std.Result.ok (keep op))
    (exitOf : Op → X)
    (hmapping : ∀ op ∈ pool, mappingInst.call mapping op = Aeneas.Std.Result.ok (exitOf op))
    (message : X → RVoluntaryExit) (toSpec : X → SignedVoluntaryExit)
    (hmessage : ∀ op ∈ pool,
      (toSpec (exitOf op)).message.validatorIndex = u64ToSpec (message (exitOf op)).validator_index ∧
      (toSpec (exitOf op)).message.epoch = u64ToSpec (message (exitOf op)).epoch)
    (hkeys : pool.Pairwise fun a b =>
      (message (exitOf a)).validator_index ≠ (message (exitOf b)).validator_index)
    {view : StateView} {s s₁ s₂ : BeaconState} (hcorr : StateCorr view s)
    {initial excl : operation_pool.IndexSet}
    {rustProposerSlashings :
      Aeneas.Std.Slice operation_pool.types.slashing.proposer_slashing.ProposerSlashing}
    {rustAttesterIndices : List (Aeneas.Std.Slice Aeneas.Std.U64 × Aeneas.Std.Slice Aeneas.Std.U64)}
    (hexcl : operation_pool.exclusionSet initial rustProposerSlashings rustAttesterIndices =
      Aeneas.Std.Result.ok excl)
    (proposerSlashings : Array ProposerSlashing) (attesterSlashings : Array AttesterSlashing)
    (hproposers : ∀ ps ∈ proposerSlashings, ∃ r ∈ rustProposerSlashings.val,
      u64ToSpec r.signed_header_1.message.proposer_index = ps.signedHeader1.message.proposerIndex)
    (hattesters : ∀ asl ∈ attesterSlashings, ∃ p ∈ rustAttesterIndices,
      asl.attestation1.attestingIndices.toArray.toList = p.1.val.map u64ToSpec ∧
      asl.attestation2.attestingIndices.toArray.toList = p.2.val.map u64ToSpec)
    (hslash₁ : runPure (ForM.forM proposerSlashings
      (processProposerSlashing (StateTransition := FuluRun))) s = .ok ((), s₁))
    (hslash₂ : runPure (ForM.forM attesterSlashings
      (processAttesterSlashing (StateTransition := FuluRun))) s₁ = .ok ((), s₂))
    (hkeep : ∀ op ∈ pool, keep op = true →
      (message (exitOf op)).validator_index ∉ excl.toList ∧
      CoresOk view (message (exitOf op)) ∧
      ExitSigned s (toSpec (exitOf op)))
    (hroom : exitStart s₂ + limit.val * exitStep (2 ^ 64 - 1) +
      Const.minValidatorWithdrawabilityDelay.toNat < 2 ^ 64) :
    ∃ out s₃, operation_pool.filter_limit_operations iterInst filterInst mappingInst cloneInst
        operations filter mapping limit = Aeneas.Std.Result.ok out ∧
      out.val.length ≤ limit.val ∧
      runPure (processVoluntaryExits (out.val.map toSpec).toArray) s₂ = .ok ((), s₃) := by
  obtain ⟨out, hout, hlen, hrun⟩ := packed_exits_valid_after_slashings iterInst filterInst
    mappingInst cloneInst operations filter mapping limit hinto hyields keep hfilter exitOf
    hmapping message toSpec hmessage hkeys hcorr hexcl proposerSlashings attesterSlashings
    hproposers hattesters hslash₁ hslash₂ hkeep
  obtain ⟨s₃, hs₃⟩ := hrun (ExitRoomAt.of_uniform s _ (by simpa using hlen) hroom)
  exact ⟨out, s₃, hout, hlen, hs₃⟩

end

end OperationPool
