import Aeneas
import EthCLSpecs.Fulu.Operations

/-!
# Scalars: extracted Rust `u64` to the spec's `UInt64`

Aeneas models a Rust `u64` as `Aeneas.Std.U64`, a wrapper around `BitVec 64`. Etheorem's spec
uses core `UInt64`. Both wrap the same bit vector, so the conversion is the identity on bits and
on the natural-number value. Statements that cross the bridge are phrased over `Nat` values.
-/

namespace OperationPool.Bridge

/-- The spec's `UInt64` for an extracted Rust `u64`. -/
def u64ToSpec (x : Aeneas.Std.U64) : UInt64 := UInt64.ofBitVec x.bv

@[simp] theorem u64ToSpec_toNat (x : Aeneas.Std.U64) : (u64ToSpec x).toNat = x.val := rfl

theorem u64ToSpec_inj {x y : Aeneas.Std.U64} (h : u64ToSpec x = u64ToSpec y) : x = y := by
  have hbv : x.bv = y.bv := by
    have := congrArg UInt64.toBitVec h
    simpa [u64ToSpec] using this
  cases x; cases y; simp_all

end OperationPool.Bridge
