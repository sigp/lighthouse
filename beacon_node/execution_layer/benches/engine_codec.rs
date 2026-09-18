//! Engine REST/SSZ vs JSON-RPC codec microbenchmarks (Paris -> Osaka).
//!
//! Measures the pure serde cost (encode/decode) of the engine API wire formats,
//! isolated from HTTP, auth, EL execution and network.
#![allow(clippy::unwrap_used)]

#[path = "fixtures.rs"]
mod fixtures;

use criterion::{Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use execution_layer::json_structures::*;
use execution_layer::ssz_structures::*;
use fixtures::*;
use ssz::{Decode, Encode};
use std::hint::black_box;
use types::ForkName;

macro_rules! transport_group {
    ($c:expr, $name:expr, $ssz:expr, $ssz_decode:expr, $json:expr, $json_ty:ty) => {{
        let ssz = $ssz;
        let json = $json;

        let ssz_bytes = ssz.as_ssz_bytes();
        let json_bytes = serde_json::to_vec(&json).unwrap();

        eprintln!(
            "{}: ssz={} json={} ({:.0}% of json)",
            $name,
            ssz_bytes.len(),
            json_bytes.len(),
            100.0 * ssz_bytes.len() as f64 / json_bytes.len() as f64,
        );

        let mut group = $c.benchmark_group($name);
        group.sampling_mode(SamplingMode::Flat);

        group.throughput(Throughput::Bytes(ssz_bytes.len() as u64));
        group.bench_function("ssz_encode", |b| b.iter(|| black_box(ssz.as_ssz_bytes())));
        group.bench_function("ssz_decode", |b| {
            b.iter(|| black_box($ssz_decode(&ssz_bytes)))
        });

        group.throughput(Throughput::Bytes(json_bytes.len() as u64));
        group.bench_function("json_encode", |b| {
            b.iter(|| black_box(serde_json::to_vec(&json).unwrap()))
        });
        group.bench_function("json_decode_via_value", |b| {
            b.iter(|| {
                let value: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
                black_box(serde_json::from_value::<$json_ty>(value).unwrap())
            })
        });

        group.finish();
    }};
}

fn bench_new_payload(c: &mut Criterion) {
    let fixture = bellatrix_new_payload(DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "newPayload_bellatrix",
        fixture.ssz,
        |b: &[u8]| SszExecutionPayloadEnvelopeBellatrix::<E>::from_ssz_bytes(b).unwrap(),
        fixture.json,
        JsonExecutionPayloadBellatrix<E>
    );

    let fixture = capella_new_payload(DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "newPayload_capella",
        fixture.ssz,
        |b: &[u8]| SszExecutionPayloadEnvelopeCapella::<E>::from_ssz_bytes(b).unwrap(),
        fixture.json,
        JsonExecutionPayloadCapella<E>
    );

    let fixture = deneb_new_payload(DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "newPayload_deneb",
        fixture.ssz,
        |b: &[u8]| SszExecutionPayloadEnvelopeDeneb::<E>::from_ssz_bytes(b).unwrap(),
        fixture.json,
        JsonExecutionPayloadDeneb<E>
    );

    let fixture = electra_new_payload(DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "newPayload_electra",
        fixture.ssz,
        |b: &[u8]| SszExecutionPayloadEnvelopeElectra::<E>::from_ssz_bytes(b).unwrap(),
        fixture.json,
        JsonExecutionPayloadElectra<E>
    );

    let fixture = fulu_new_payload(DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "newPayload_fulu",
        fixture.ssz,
        |b: &[u8]| SszExecutionPayloadEnvelopeFulu::<E>::from_ssz_bytes(b).unwrap(),
        fixture.json,
        JsonExecutionPayloadFulu<E>
    );
}

fn bench_get_payload(c: &mut Criterion) {
    let fixture = bellatrix_get_payload(DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "getPayload_bellatrix",
        fixture.ssz,
        |b: &[u8]| SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(b, ForkName::Bellatrix)
            .unwrap(),
        fixture.json,
        JsonGetPayloadResponseBellatrix<E>
    );

    let fixture = capella_get_payload(DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "getPayload_capella",
        fixture.ssz,
        |b: &[u8]| SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(b, ForkName::Capella)
            .unwrap(),
        fixture.json,
        JsonGetPayloadResponseCapella<E>
    );

    let fixture = deneb_get_payload(DEFAULT_TX_COUNT, DEFAULT_BUNDLE_BLOB_COUNT);
    transport_group!(
        c,
        "getPayload_deneb",
        fixture.ssz,
        |b: &[u8]| SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(b, ForkName::Deneb).unwrap(),
        fixture.json,
        JsonGetPayloadResponseDeneb<E>
    );

    let fixture = electra_get_payload(DEFAULT_TX_COUNT, DEFAULT_BUNDLE_BLOB_COUNT);
    transport_group!(
        c,
        "getPayload_electra",
        fixture.ssz,
        |b: &[u8]| SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(b, ForkName::Electra)
            .unwrap(),
        fixture.json,
        JsonGetPayloadResponseElectra<E>
    );

    for &n in &TX_COUNT_SWEEP {
        let fixture = fulu_get_payload(n, DEFAULT_BUNDLE_BLOB_COUNT);
        transport_group!(
            c,
            format!("getPayload_fulu_{n}txs"),
            fixture.ssz,
            |b: &[u8]| SszGetPayloadResponse::<E>::from_ssz_bytes_by_fork(b, ForkName::Fulu)
                .unwrap(),
            fixture.json,
            JsonGetPayloadResponseFulu<E>
        );
    }
}

fn bench_get_blobs(c: &mut Criterion) {
    let fixture = fulu_blobs(DEFAULT_BUNDLE_BLOB_COUNT);
    transport_group!(
        c,
        "getBlobs_v2_fulu",
        fixture.ssz.clone(),
        |b: &[u8]| SszBlobsResponse::<E>::from_ssz_bytes(b).unwrap(),
        fixture.json_v2,
        Vec<BlobAndProofV2<E>>
    );
    transport_group!(
        c,
        "getBlobs_v3_fulu",
        fixture.ssz,
        |b: &[u8]| SszBlobsResponse::<E>::from_ssz_bytes(b).unwrap(),
        fixture.json_v3,
        Vec<BlobAndProofV3<E>>
    );
}

fn bench_get_payload_bodies(c: &mut Criterion) {
    let fixture = bellatrix_bodies(DEFAULT_BODIES_COUNT, DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "getPayloadBodies_bellatrix",
        fixture.ssz,
        |b: &[u8]| SszBodiesResponse::<E>::from_ssz_bytes_by_fork(b, ForkName::Bellatrix).unwrap(),
        fixture.json,
        Vec<Option<JsonExecutionPayloadBodyV1<E>>>
    );

    let fixture = fulu_bodies(DEFAULT_BODIES_COUNT, DEFAULT_TX_COUNT);
    transport_group!(
        c,
        "getPayloadBodies_fulu",
        fixture.ssz,
        |b: &[u8]| SszBodiesResponse::<E>::from_ssz_bytes_by_fork(b, ForkName::Fulu).unwrap(),
        fixture.json,
        Vec<Option<JsonExecutionPayloadBodyV1<E>>>
    );
}

criterion_group!(
    benches,
    bench_new_payload,
    bench_get_payload,
    bench_get_blobs,
    bench_get_payload_bodies
);
criterion_main!(benches);
