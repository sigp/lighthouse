// These would usually be created by superstuct but now there's no longer a 1:1 mapping between
// the variants for ExecutionPayload and the variants for
// - ExecutionPayloadHeader
// - FullPayload
// - BlindedPayload

#[macro_export]
macro_rules! map_execution_payload_into_full_payload {
    ($value:expr, $f:expr) => {
        match $value {
            ExecutionPayload::Bellatrix(inner) => {
                let f: fn(ExecutionPayloadBellatrix<_>, fn(_) -> _) -> _ = $f;
                f(inner, FullPayload::Bellatrix)
            }
            ExecutionPayload::Capella(inner) => {
                let f: fn(ExecutionPayloadCapella<_>, fn(_) -> _) -> _ = $f;
                f(inner, FullPayload::Capella)
            }
            ExecutionPayload::Deneb(inner) => {
                let f: fn(ExecutionPayloadDeneb<_>, fn(_) -> _) -> _ = $f;
                f(inner, FullPayload::Deneb)
            }
            ExecutionPayload::Electra(inner) => {
                let f: fn(ExecutionPayloadElectra<_>, fn(_) -> _) -> _ = $f;
                f(inner, FullPayload::Electra)
            }
            ExecutionPayload::EIP7732(_) => panic!("FullPayload::EIP7732 does not exist!"),
        }
    };
}

#[macro_export]
macro_rules! map_execution_payload_into_blinded_payload {
    ($value:expr, $f:expr) => {
        match $value {
            ExecutionPayload::Bellatrix(inner) => {
                let f: fn(ExecutionPayloadBellatrix<_>, fn(_) -> _) -> _ = $f;
                f(inner, BlindedPayload::Bellatrix)
            }
            ExecutionPayload::Capella(inner) => {
                let f: fn(ExecutionPayloadCapella<_>, fn(_) -> _) -> _ = $f;
                f(inner, BlindedPayload::Capella)
            }
            ExecutionPayload::Deneb(inner) => {
                let f: fn(ExecutionPayloadDeneb<_>, fn(_) -> _) -> _ = $f;
                f(inner, BlindedPayload::Deneb)
            }
            ExecutionPayload::Electra(inner) => {
                let f: fn(ExecutionPayloadElectra<_>, fn(_) -> _) -> _ = $f;
                f(inner, BlindedPayload::Electra)
            }
            ExecutionPayload::EIP7732(_) => panic!("BlindedPayload::EIP7732 does not exist!"),
        }
    };
}

#[macro_export]
macro_rules! map_execution_payload_ref_into_execution_payload_header {
    (&$lifetime:tt _, $value:expr, $f:expr) => {
        match $value {
            ExecutionPayloadRef::Bellatrix(inner) => {
                let f: fn(
                    &$lifetime ExecutionPayloadBellatrix<_>,
                    fn(_) -> _,
                ) -> _ = $f;
                f(inner, ExecutionPayloadHeader::Bellatrix)
            }
            ExecutionPayloadRef::Capella(inner) => {
                let f: fn(
                    &$lifetime ExecutionPayloadCapella<_>,
                    fn(_) -> _,
                ) -> _ = $f;
                f(inner, ExecutionPayloadHeader::Capella)
            }
            ExecutionPayloadRef::Deneb(inner) => {
                let f: fn(
                    &$lifetime ExecutionPayloadDeneb<_>,
                    fn(_) -> _,
                ) -> _ = $f;
                f(inner, ExecutionPayloadHeader::Deneb)
            }
            ExecutionPayloadRef::Electra(inner) => {
                let f: fn(
                    &$lifetime ExecutionPayloadElectra<_>,
                    fn(_) -> _,
                ) -> _ = $f;
                f(inner, ExecutionPayloadHeader::Electra)
            }
            ExecutionPayloadRef::EIP7732(_) => panic!("ExecutionPayloadHeader::EIP7732 does not exist!"),
        }
    }
}
