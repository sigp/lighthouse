//! Deterministic fixtures for the engine-codec benchmarks, assembled from the
//! reused mock-EL generators in `execution_layer::test_utils`.

use execution_layer::json_structures::*;
use execution_layer::ssz_structures::*;
use execution_layer::test_utils::*;
use execution_layer::*;
use ssz_types::{ProgressiveVariableList, VariableList};
use types::{
    BlockAccessList, EthSpec, ExecutionPayloadBellatrix, ExecutionPayloadCapella,
    ExecutionPayloadDeneb, ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionPayloadGloas,
    ExecutionRequestsElectra, ExecutionRequestsGloas, ForkName, Hash256, MainnetEthSpec,
    ProgressiveTransactions, Transactions, Uint256,
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
/// Block access list size (EIP-7928, Gloas+). The BAL is opaque bytes on both wires, so its size
/// is ours to choose; tens of KB is the order a full mainnet block is expected to carry.
pub const DEFAULT_BAL_BYTES: usize = 32 * 1024;
/// BAL scaling sweep. The zero point is the useful one: it isolates the Gloas progressive-list
/// framing from the BAL itself, the way the Capella -> Deneb step isolates blobs.
pub const BAL_BYTE_SWEEP: [usize; 3] = [0, 32 * 1024, 128 * 1024];
/// Cells per blob in a `/blobs/v4` response: the PeerDAS reconstruction threshold
/// (`CellsPerExtBlob / 2`), i.e. the largest single fetch a reconstructing node would make.
pub const DEFAULT_V4_CELL_COUNT: usize = 64;

/// `n_txs` copies of a real, valid transaction.
fn transactions(n_txs: usize) -> Transactions<E> {
    let tx = static_valid_tx::<E>().expect("static valid tx");
    vec![tx; n_txs].try_into().expect("transactions within cap")
}

/// `n_txs` copies of a real, valid transaction, in the Gloas progressive container.
fn progressive_transactions(n_txs: usize) -> ProgressiveTransactions {
    let tx = static_valid_tx::<E>().expect("static valid tx");
    let tx = ProgressiveVariableList::new(tx.to_vec()).expect("tx bytes");
    ProgressiveVariableList::new(vec![tx; n_txs]).expect("transactions")
}

/// An opaque EIP-7928 block access list of `n_bytes`.
///
/// The contents are deterministic filler. Only the length moves the numbers: SSZ memcpys the blob
/// and JSON hex-encodes it at two chars per byte, neither of which looks at the values.
fn block_access_list(n_bytes: usize) -> BlockAccessList {
    let bytes = (0..n_bytes).map(|i| (i % 251) as u8).collect();
    ProgressiveVariableList::new(bytes).expect("block access list")
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

/// A Gloas execution payload: progressive tx/withdrawal containers plus an `n_bal_bytes` BAL.
pub fn gloas_execution_payload(n_txs: usize, n_bal_bytes: usize) -> ExecutionPayloadGloas<E> {
    ExecutionPayloadGloas {
        transactions: progressive_transactions(n_txs),
        block_access_list: block_access_list(n_bal_bytes),
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

pub fn gloas_new_payload(
    n_txs: usize,
    n_bal_bytes: usize,
) -> NewPayloadFixture<SszExecutionPayloadEnvelopeGloas<E>, JsonExecutionPayloadGloas<E>> {
    let payload = gloas_execution_payload(n_txs, n_bal_bytes);
    let requests = ExecutionRequestsGloas::<E>::default();

    let json = payload.clone().try_into().expect("json payload");

    let request = NewPayloadRequestGloas {
        execution_payload: &payload,
        versioned_hashes: vec![],
        parent_beacon_block_root: Hash256::default(),
        execution_requests: &requests,
    };
    let ssz = SszExecutionPayloadEnvelopeGloas::try_from(request).expect("ssz envelope");

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

pub fn gloas_get_payload(
    n_txs: usize,
    n_blobs: usize,
    n_bal_bytes: usize,
) -> GetPayloadFixture<JsonGetPayloadResponseGloas<E>> {
    let (blobs_bundle, _) = generate_blobs::<E>(n_blobs, ForkName::Gloas).expect("blobs bundle");

    let response = GetPayloadResponse::Gloas(GetPayloadResponseGloas {
        execution_payload: gloas_execution_payload(n_txs, n_bal_bytes),
        block_value: Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI),
        blobs_bundle,
        should_override_builder: false,
        requests: ExecutionRequestsGloas::<E>::default(),
    });

    let ssz = SszGetPayloadResponse::try_from(response.clone()).expect("ssz get_payload");
    let JsonGetPayloadResponse::Gloas(json) =
        JsonGetPayloadResponse::try_from(response).expect("json get_payload")
    else {
        unreachable!("gloas response yields gloas json")
    };

    GetPayloadFixture { ssz, json }
}

pub struct BlobsFixture {
    pub ssz: SszBlobsResponseV2<E>,
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
        .map(|contents| BlobsEntryV2 {
            available: true,
            contents,
        })
        .collect::<Vec<_>>();
    let ssz = SszBlobsResponseV2 {
        entries: VariableList::new(entries).expect("entries within cap"),
    };

    let json_v3 = contents.iter().cloned().map(Some).collect();

    BlobsFixture {
        ssz,
        json_v2: contents,
        json_v3,
    }
}

/// Paired SSZ/JSON wire objects for a `/blobs/v4` response (decode-focus).
///
/// v4 is cell-level, not blob-level: a reconstructing node asks for the cells it is missing, so the
/// response carries `n_cells` cells and their KZG cell proofs per blob rather than whole blobs.
pub struct BlobsV4Fixture {
    pub ssz: SszBlobsResponseV4<E>,
    pub json: GetBlobsV4List<E>,
}

pub fn gloas_blobs_v4(n_blobs: usize, n_cells: usize) -> BlobsV4Fixture {
    let (bundle, _) = generate_blobs::<E>(n_blobs, ForkName::Gloas).expect("blobs bundle");
    let cells = load_test_blob_cells::<E>().expect("test blob cells");
    let cells_per_blob = E::cells_per_ext_blob();
    assert!(
        n_cells <= cells_per_blob,
        "n_cells exceeds cells per ext blob"
    );

    let contents: Vec<BlobCellsAndProofsV1<E>> = (0..n_blobs)
        .map(|i| {
            let start = i * cells_per_blob;
            let proofs = bundle
                .proofs
                .get(start..start + n_cells)
                .expect("cell proofs present");
            BlobCellsAndProofsV1 {
                blob_cells: cells
                    .iter()
                    .take(n_cells)
                    .cloned()
                    .map(|cell| Some(JsonCell(cell)))
                    .collect(),
                proofs: proofs.iter().copied().map(Some).collect(),
            }
        })
        .collect();

    let entries = contents
        .iter()
        .cloned()
        .map(|contents| BlobsEntryV4 {
            available: true,
            contents: SszBlobCellsAndProofs::try_from(contents).expect("ssz cells and proofs"),
        })
        .collect::<Vec<_>>();
    let ssz = SszBlobsResponseV4 {
        entries: VariableList::new(entries).expect("entries within cap"),
    };

    let json = contents.into_iter().map(Some).collect();

    BlobsV4Fixture { ssz, json }
}

pub struct BodiesFixture<S, J> {
    pub ssz: S,
    pub json: J,
}

pub fn fulu_bodies(
    n_bodies: usize,
    n_txs: usize,
) -> BodiesFixture<SszBodiesResponseV2<E>, Vec<Option<JsonExecutionPayloadBodyV1<E>>>> {
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

pub fn bellatrix_bodies(
    n_bodies: usize,
    n_txs: usize,
) -> BodiesFixture<SszBodiesResponseV1<E>, Vec<Option<JsonExecutionPayloadBodyV1<E>>>> {
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

/// A Gloas (V3) bodies response.
///
/// The pairing here is forced, not chosen: `from_ssz_bytes_by_fork` maps Gloas to V3, and
/// `into_bodies()` rejects V3, so the v1 engine method cannot serve a Gloas body at all. Only
/// `get_payload_bodies_by_hash_v2` applies, whose JSON-RPC type is `JsonExecutionPayloadBodyV2`.
pub fn gloas_bodies(
    n_bodies: usize,
    n_txs: usize,
    n_bal_bytes: usize,
) -> BodiesFixture<SszBodiesResponseV3<E>, Vec<Option<JsonExecutionPayloadBodyV2<E>>>> {
    let body = ExecutionPayloadBodyV2::<E> {
        transactions: progressive_transactions(n_txs),
        withdrawals: Some(ProgressiveVariableList::empty()),
        block_access_list: Some(block_access_list(n_bal_bytes)),
    };

    let entries = (0..n_bodies)
        .map(|_| SszBodyEntryV3 {
            available: true,
            body: SszExecutionPayloadBodyV3::try_from(body.clone()).expect("ssz body"),
        })
        .collect::<Vec<_>>();
    let ssz = SszBodiesResponseV3 {
        entries: VariableList::new(entries).expect("entries within cap"),
    };

    let json = (0..n_bodies)
        .map(|_| Some(JsonExecutionPayloadBodyV2::try_from(body.clone()).expect("json body")))
        .collect();

    BodiesFixture { ssz, json }
}
