-- External types that both extracted crates refer to.
--
-- Aeneas declares an external type at the root namespace, so two extracted crates that mention the
-- same type would each declare it. The shared ones live here, and each crate's `TypesExternal.lean`
-- imports this file.
--
-- Everything in this file is TRUSTED, and left opaque: nothing is assumed about these types
-- beyond their existence.
import Aeneas
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/-- [blst::min_pk::PublicKey] -/
@[rust_type "blst::min_pk::PublicKey"]
axiom blst.min_pk.PublicKey : Type
