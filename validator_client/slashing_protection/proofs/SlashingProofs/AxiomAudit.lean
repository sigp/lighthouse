import SlashingProofs.Soundness
import Lean.Util.CollectAxioms

/-!
# Axiom audit

Walks every theorem under `SlashingProofs` and fails if one depends on an axiom outside the
three standard ones, or if the library declares an axiom of its own. A `sorry` anywhere
beneath a theorem shows up as `sorryAx`, so this also rejects incomplete proofs.

This runs at elaboration time, so `lake build` fails on a violation. CI also runs it directly
with `lake env lean SlashingProofs/AxiomAudit.lean`, since Lake can replay a cached log.
-/

open Lean Elab Command

namespace SlashingProofs

def allowedAxioms : List Name := [``propext, ``Classical.choice, ``Quot.sound]

run_cmd do
  let env ← getEnv
  let mut theorems := 0
  let mut violations : Array MessageData := #[]
  for (declName, info) in env.constants.toList do
    let some idx := env.getModuleIdxFor? declName | continue
    let moduleName := env.header.moduleNames[idx]!
    unless Name.isPrefixOf `SlashingProofs moduleName do continue
    match info with
    | .thmInfo _ =>
      let axioms ← collectAxioms declName
      theorems := theorems + 1
      for ax in axioms do
        unless allowedAxioms.contains ax do
          violations := violations.push m!"{declName} depends on {ax}"
    | .axiomInfo _ =>
      violations := violations.push m!"{declName} is declared as an axiom"
    | _ => pure ()
  if theorems == 0 then
    throwError "no theorems found under SlashingProofs"
  unless violations.isEmpty do
    throwError m!"axiom audit failed:\n{MessageData.joinSep violations.toList "\n"}"
  logInfo m!"audited {theorems} theorems, all within {allowedAxioms}"

end SlashingProofs
