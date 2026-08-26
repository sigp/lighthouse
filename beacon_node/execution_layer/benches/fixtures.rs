//! Deterministic fixtures for the engine-codec benchmarks, assembled from the
//! reused mock-EL generators in `execution_layer::test_utils`.

use execution_layer::json_structures::*;
use execution_layer::ssz_structures::*;
use execution_layer::test_utils::*;
use execution_layer::*;
use ssz_types::VariableList;
use types::{
    EthSpec, ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
    ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionRequestsElectra, ForkName, Hash256,
    MainnetEthSpec, Transactions, Uint256,
};

/// EthSpec used across the benchmarks.
pub type E = MainnetEthSpec;

/// Default transaction count — a small-to-mid mainnet block.
pub const DEFAULT_TX_COUNT: usize = 150;
/// Transaction-count scaling sweep: near-empty, small-mid, busy block.
pub const TX_COUNT_SWEEP: [usize; 3] = [10, 150, 500];
/// Blobs per bundle (get_blobs / get_payload bundle); decoupled from tx count.
pub const DEFAULT_BUNDLE_BLOB_COUNT: usize = 6;
/// Bodies per getPayloadBodies response.
pub const DEFAULT_BODIES_COUNT: usize = 32;

/// `n_txs` copies of a real, valid transaction.
fn transactions(n_txs: usize) -> Transactions<E> {
    let tx = static_valid_tx::<E>().expect("static valid tx");
    vec![tx; n_txs].try_into().expect("transactions within cap")
}

pub fn bellatrix_execution_payload(n_txs: usize) -> ExecutionPayloadBellatrix<E> {
    ExecutionPayloadBellatrix {
        transactions: transactions(n_txs),
        ..Default::default()
    }
}

pub fn capella_execution_payload(n_txs: usize) -> ExecutionPayloadCapella<E> {
    ExecutionPayloadCapella {
        transactions: transactions(n_txs),
        ..Default::default()
    }
}

pub fn deneb_execution_payload(n_txs: usize) -> ExecutionPayloadDeneb<E> {
    ExecutionPayloadDeneb {
        transactions: transactions(n_txs),
        ..Default::default()
    }
}

pub fn electra_execution_payload(n_txs: usize) -> ExecutionPayloadElectra<E> {
    ExecutionPayloadElectra {
        transactions: transactions(n_txs),
        ..Default::default()
    }
}

/// A Fulu execution payload carrying `n_txs` real transactions.
pub fn fulu_execution_payload(n_txs: usize) -> ExecutionPayloadFulu<E> {
    ExecutionPayloadFulu {
        transactions: transactions(n_txs),
        ..Default::default()
    }
}

/// Paired SSZ/JSON wire objects for the Fulu `new_payload` request (encode-focus).
///
/// SSZ is the REST envelope (payload + parent root + requests); JSON is the payload the JSON-RPC
/// params array carries. Both are built from one source payload.
pub struct NewPayloadFixture<S, J> {
    pub ssz: S,
    pub json: J,
}

pub fn fulu_new_payload(
    n_txs: usize,
) -> NewPayloadFixture<SszExecutionPayloadEnvelopeFulu<E>, JsonExecutionPayloadFulu<E>> {
    let payload = fulu_execution_payload(n_txs);
    let requests = ExecutionRequestsElectra::<E>::default();

    let json = payload.clone().try_into().expect("json payload");

    let request = NewPayloadRequestFulu {
        execution_payload: &payload,
        versioned_hashes: vec![],
        parent_beacon_block_root: Hash256::default(),
        execution_requests: &requests,
    };
    let ssz = SszExecutionPayloadEnvelopeFulu::try_from(request).expect("ssz envelope");

    NewPayloadFixture { ssz, json }
}

pub fn bellatrix_new_payload(
    n_txs: usize,
) -> NewPayloadFixture<SszExecutionPayloadEnvelopeBellatrix<E>, JsonExecutionPayloadBellatrix<E>> {
    let payload = bellatrix_execution_payload(n_txs);

    let json = payload.clone().into();

    let request = NewPayloadRequestBellatrix {
        execution_payload: &payload,
    };
    let ssz = SszExecutionPayloadEnvelopeBellatrix::from(request);

    NewPayloadFixture { ssz, json }
}

pub fn capella_new_payload(
    n_txs: usize,
) -> NewPayloadFixture<SszExecutionPayloadEnvelopeCapella<E>, JsonExecutionPayloadCapella<E>> {
    let payload = capella_execution_payload(n_txs);

    let json = payload.clone().try_into().expect("json payload");

    let request = NewPayloadRequestCapella {
        execution_payload: &payload,
    };
    let ssz = SszExecutionPayloadEnvelopeCapella::from(request);

    NewPayloadFixture { ssz, json }
}

pub fn deneb_new_payload(
    n_txs: usize,
) -> NewPayloadFixture<SszExecutionPayloadEnvelopeDeneb<E>, JsonExecutionPayloadDeneb<E>> {
    let payload = deneb_execution_payload(n_txs);

    let json = payload.clone().try_into().expect("json payload");

    let request = NewPayloadRequestDeneb {
        execution_payload: &payload,
        versioned_hashes: vec![],
        parent_beacon_block_root: Hash256::default(),
    };
    let ssz = SszExecutionPayloadEnvelopeDeneb::from(request);

    NewPayloadFixture { ssz, json }
}

pub fn electra_new_payload(
    n_txs: usize,
) -> NewPayloadFixture<SszExecutionPayloadEnvelopeElectra<E>, JsonExecutionPayloadElectra<E>> {
    let payload = electra_execution_payload(n_txs);
    let requests = ExecutionRequestsElectra::<E>::default();

    let json = payload.clone().try_into().expect("json payload");

    let request = NewPayloadRequestElectra {
        execution_payload: &payload,
        versioned_hashes: vec![],
        parent_beacon_block_root: Hash256::default(),
        execution_requests: &requests,
    };
    let ssz = SszExecutionPayloadEnvelopeElectra::try_from(request).expect("ssz envelope");

    NewPayloadFixture { ssz, json }
}

pub struct GetPayloadFixture<J> {
    pub ssz: SszGetPayloadResponse<E>,
    pub json: J,
}

pub fn fulu_get_payload(
    n_txs: usize,
    n_blobs: usize,
) -> GetPayloadFixture<JsonGetPayloadResponseFulu<E>> {
    let (blobs_bundle, _) = generate_blobs::<E>(n_blobs, ForkName::Fulu).expect("blobs bundle");

    let response = GetPayloadResponse::Fulu(GetPayloadResponseFulu {
        execution_payload: fulu_execution_payload(n_txs),
        block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
        blobs_bundle,
        should_override_builder: false,
        requests: ExecutionRequestsElectra::<E>::default(),
    });

    let ssz = SszGetPayloadResponse::try_from(response.clone()).expect("ssz get_payload");
    let JsonGetPayloadResponse::Fulu(json) =
        JsonGetPayloadResponse::try_from(response).expect("json get_payload")
    else {
        unreachable!("fulu response yields fulu json")
    };

    GetPayloadFixture { ssz, json }
}

pub fn bellatrix_get_payload(
    n_txs: usize,
) -> GetPayloadFixture<JsonGetPayloadResponseBellatrix<E>> {
    let response = GetPayloadResponse::Bellatrix(GetPayloadResponseBellatrix {
        execution_payload: bellatrix_execution_payload(n_txs),
        block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
    });

    let ssz = SszGetPayloadResponse::try_from(response.clone()).expect("ssz get_payload");
    let JsonGetPayloadResponse::Bellatrix(json) =
        JsonGetPayloadResponse::try_from(response).expect("json get_payload")
    else {
        unreachable!("bellatrix response yields bellatrix json")
    };

    GetPayloadFixture { ssz, json }
}

pub fn capella_get_payload(n_txs: usize) -> GetPayloadFixture<JsonGetPayloadResponseCapella<E>> {
    let response = GetPayloadResponse::Capella(GetPayloadResponseCapella {
        execution_payload: capella_execution_payload(n_txs),
        block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
    });

    let ssz = SszGetPayloadResponse::try_from(response.clone()).expect("ssz get_payload");
    let JsonGetPayloadResponse::Capella(json) =
        JsonGetPayloadResponse::try_from(response).expect("json get_payload")
    else {
        unreachable!("capella response yields capella json")
    };

    GetPayloadFixture { ssz, json }
}

pub fn deneb_get_payload(
    n_txs: usize,
    n_blobs: usize,
) -> GetPayloadFixture<JsonGetPayloadResponseDeneb<E>> {
    let (blobs_bundle, _) = generate_blobs::<E>(n_blobs, ForkName::Deneb).expect("blobs bundle");

    let response = GetPayloadResponse::Deneb(GetPayloadResponseDeneb {
        execution_payload: deneb_execution_payload(n_txs),
        block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
        blobs_bundle,
        should_override_builder: false,
    });

    let ssz = SszGetPayloadResponse::try_from(response.clone()).expect("ssz get_payload");
    let JsonGetPayloadResponse::Deneb(json) =
        JsonGetPayloadResponse::try_from(response).expect("json get_payload")
    else {
        unreachable!("deneb response yields deneb json")
    };

    GetPayloadFixture { ssz, json }
}

pub fn electra_get_payload(
    n_txs: usize,
    n_blobs: usize,
) -> GetPayloadFixture<JsonGetPayloadResponseElectra<E>> {
    let (blobs_bundle, _) = generate_blobs::<E>(n_blobs, ForkName::Electra).expect("blobs bundle");

    let response = GetPayloadResponse::Electra(GetPayloadResponseElectra {
        execution_payload: electra_execution_payload(n_txs),
        block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
        blobs_bundle,
        should_override_builder: false,
        requests: ExecutionRequestsElectra::<E>::default(),
    });

    let ssz = SszGetPayloadResponse::try_from(response.clone()).expect("ssz get_payload");
    let JsonGetPayloadResponse::Electra(json) =
        JsonGetPayloadResponse::try_from(response).expect("json get_payload")
    else {
        unreachable!("electra response yields electra json")
    };

    GetPayloadFixture { ssz, json }
}

pub struct BlobsFixture {
    pub ssz: SszBlobsResponse<E>,
    pub json_v2: Vec<BlobAndProofV2<E>>,
    pub json_v3: Vec<BlobAndProofV3<E>>,
}

pub fn fulu_blobs(n_blobs: usize) -> BlobsFixture {
    let (bundle, _) = generate_blobs::<E>(n_blobs, ForkName::Fulu).expect("blobs bundle");
    let cells = E::cells_per_ext_blob();

    let contents: Vec<BlobAndProofV2<E>> = (0..n_blobs)
        .map(|i| {
            let blob = bundle.blobs.get(i).expect("blob present").clone();
            let start = i * cells;
            let proofs = bundle
                .proofs
                .get(start..start + cells)
                .expect("cell proofs present")
                .to_vec()
                .try_into()
                .expect("cell proofs within cap");
            BlobAndProofV2 { blob, proofs }
        })
        .collect();

    let entries = contents
        .iter()
        .cloned()
        .map(|contents| BlobsEntry {
            available: true,
            contents,
        })
        .collect::<Vec<_>>();
    let ssz = SszBlobsResponse {
        entries: VariableList::new(entries).expect("entries within cap"),
    };

    let json_v3 = contents.iter().cloned().map(Some).collect();

    BlobsFixture {
        ssz,
        json_v2: contents,
        json_v3,
    }
}

pub struct BodiesFixture<S> {
    pub ssz: S,
    pub json: Vec<Option<JsonExecutionPayloadBodyV1<E>>>,
}

pub fn fulu_bodies(n_bodies: usize, n_txs: usize) -> BodiesFixture<SszBodiesResponseV2<E>> {
    let payload = fulu_execution_payload(n_txs);
    let body = ExecutionPayloadBodyV1 {
        transactions: payload.transactions.clone(),
        withdrawals: Some(payload.withdrawals.clone()),
    };

    let entries = (0..n_bodies)
        .map(|_| SszBodyEntryV2 {
            available: true,
            body: SszExecutionPayloadBodyV2::try_from(body.clone()).expect("ssz body"),
        })
        .collect::<Vec<_>>();
    let ssz = SszBodiesResponseV2 {
        entries: VariableList::new(entries).expect("entries within cap"),
    };

    let json = (0..n_bodies)
        .map(|_| Some(JsonExecutionPayloadBodyV1::try_from(body.clone()).expect("json body")))
        .collect();

    BodiesFixture { ssz, json }
}

pub fn bellatrix_bodies(n_bodies: usize, n_txs: usize) -> BodiesFixture<SszBodiesResponseV1<E>> {
    let body = ExecutionPayloadBodyV1 {
        transactions: transactions(n_txs),
        withdrawals: None,
    };

    let entries = (0..n_bodies)
        .map(|_| SszBodyEntryV1 {
            available: true,
            body: SszExecutionPayloadBodyV1::from(body.clone()),
        })
        .collect::<Vec<_>>();
    let ssz = SszBodiesResponseV1 {
        entries: VariableList::new(entries).expect("entries within cap"),
    };

    let json = (0..n_bodies)
        .map(|_| Some(JsonExecutionPayloadBodyV1::try_from(body.clone()).expect("json body")))
        .collect();

    BodiesFixture { ssz, json }
}
