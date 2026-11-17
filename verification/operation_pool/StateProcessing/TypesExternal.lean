-- [state_processing]: external types.
--
-- Hand-written from `TypesExternal_Template.lean`. Every type here stays opaque: the public key
-- bytes and the payloads of error variants that the `verify_exit` cores never build or inspect.
-- `blst::min_pk::PublicKey` is in `ExternalTypes.lean`, shared with the other extracted crate.
import Aeneas
import ExternalTypes
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option linter.style.whitespace false
set_option linter.style.setOption false
set_option linter.style.longLine false
set_option linter.internalConstructors false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000

/- You can set the `maxRecDepth` value with the `-max-recdepth` CLI option -/
set_option maxRecDepth 2048

/-- [bls::generic_public_key_bytes::GenericPublicKeyBytes]
    Source: 'crypto/bls/src/generic_public_key_bytes.rs', lines 20:0-20:37
    Name pattern: [bls::generic_public_key_bytes::GenericPublicKeyBytes]
    Visibility: public -/
@[rust_type "bls::generic_public_key_bytes::GenericPublicKeyBytes"]
axiom bls.generic_public_key_bytes.GenericPublicKeyBytes (Pub : Type _) : Type

/-- [ssz_types::Error]
    Source: '/cargo/git/checkouts/ssz_types-19f835ca387d51e3/8955d22/src/lib.rs', lines 86:0-86:14
    Name pattern: [ssz_types::Error]
    Visibility: public -/
@[rust_type "ssz_types::Error"]
axiom ssz_types.Error : Type

/-- [types::state::beacon_state::BeaconStateError]
    Source: 'consensus/types/src/state/beacon_state.rs', lines 97:0-97:25
    Name pattern: [types::state::beacon_state::BeaconStateError]
    Visibility: public -/
@[rust_type "types::state::beacon_state::BeaconStateError"]
axiom types.state.beacon_state.BeaconStateError : Type

/-- [state_processing::consensus_context::ContextError]
    Source: 'consensus/state_processing/src/consensus_context.rs', lines 36:0-41:1
    Visibility: public -/
axiom consensus_context.ContextError : Type

/-- [state_processing::per_block_processing::signature_sets::Error]
    Source: 'consensus/state_processing/src/per_block_processing/signature_sets.rs', lines 23:0-52:1
    Visibility: public -/
axiom per_block_processing.signature_sets.Error : Type

