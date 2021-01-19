use crate::*;
pub use constants::*;
pub use consumer::*;
pub use local_signer_test_data::*;
pub use mock::*;
use remote_signer_client::Client;
pub use remote_signer_test_data::*;
use std::fs;
use std::fs::{create_dir, File};
use std::io::Write;
use std::net::IpAddr::{V4, V6};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;
use types::{
    AggregateSignature, Attestation, AttestationData, AttesterSlashing, BeaconBlock,
    BeaconBlockHeader, BitList, Checkpoint, Deposit, DepositData, Epoch, EthSpec, FixedVector,
    Hash256, IndexedAttestation, ProposerSlashing, PublicKeyBytes, Signature, SignatureBytes,
    SignedBeaconBlockHeader, SignedVoluntaryExit, Slot, Unsigned, VariableList, VoluntaryExit,
};

pub fn get_address(client: &Client) -> String {
    let listening_address = client.get_listening_address();
    let ip = match listening_address.ip() {
        V4(ip) => ip.to_string(),
        V6(ip) => ip.to_string(),
    };

    format!("http://{}:{}", ip, listening_address.port())
}

pub fn set_permissions(path: &Path, perm_octal: u32) {
    let metadata = fs::metadata(path).unwrap();
    let mut permissions = metadata.permissions();
    permissions.set_mode(perm_octal);
    fs::set_permissions(path, permissions).unwrap();
}

pub fn add_key_files(tmp_dir: &TempDir) {
    let pairs = vec![
        (PUBLIC_KEY_1, SECRET_KEY_1),
        (PUBLIC_KEY_2, SECRET_KEY_2),
        (PUBLIC_KEY_3, SECRET_KEY_3),
    ];

    add_files(tmp_dir, pairs);
}

pub fn add_mismatched_key_file(tmp_dir: &TempDir) {
    let pairs = vec![(MISMATCHED_PUBLIC_KEY, SECRET_KEY_1)];

    add_files(tmp_dir, pairs);
}

pub fn add_invalid_secret_key_file(tmp_dir: &TempDir) {
    let pairs = vec![(PUBLIC_KEY_FOR_INVALID_SECRET_KEY, INVALID_SECRET_KEY)];

    add_files(tmp_dir, pairs);
}

pub fn add_non_key_files(tmp_dir: &TempDir) {
    let pairs = vec![
        (SILLY_FILE_NAME_1, SILLY_CONTENT_1),
        (SILLY_FILE_NAME_2, SILLY_CONTENT_2),
        (SILLY_FILE_NAME_3, SILLY_CONTENT_3),
    ];

    add_files(tmp_dir, pairs);
}

fn add_files(tmp_dir: &TempDir, pairs: Vec<(&str, &str)>) {
    for pair in pairs {
        let file_path = tmp_dir.path().join(pair.0);
        let mut tmp_file = File::create(file_path).unwrap();
        writeln!(tmp_file, "{}", pair.1).unwrap();
    }
}

pub fn add_sub_dirs(tmp_dir: &TempDir) {
    let random_sub_dir_path = tmp_dir.path().join("random_sub_dir_name");
    create_dir(random_sub_dir_path).unwrap();

    let another_sub_dir_path = tmp_dir.path().join(SUB_DIR_NAME);
    create_dir(another_sub_dir_path).unwrap();
}

/// We spice up some of the values, based on a given `seed` parameter.
pub fn get_block<E: EthSpec>(seed: u64) -> BeaconBlock<E> {
    let spec = &mut E::default_spec();
    spec.genesis_slot = Slot::new(seed);

    let header = BeaconBlockHeader {
        slot: Slot::new(seed),
        proposer_index: 0,
        parent_root: Hash256::from_low_u64_be(222 * seed),
        state_root: Hash256::from_low_u64_be(333 * seed),
        body_root: Hash256::from_low_u64_be(444 * seed),
    };

    let signed_header = SignedBeaconBlockHeader {
        message: header,
        signature: Signature::empty(),
    };
    let indexed_attestation: IndexedAttestation<E> = IndexedAttestation {
        attesting_indices: VariableList::new(vec![0_u64; E::MaxValidatorsPerCommittee::to_usize()])
            .unwrap(),
        data: AttestationData::default(),
        signature: AggregateSignature::empty(),
    };

    let deposit_data = DepositData {
        pubkey: PublicKeyBytes::empty(),
        withdrawal_credentials: Hash256::from_low_u64_be(555 * seed),
        amount: 0,
        signature: SignatureBytes::empty(),
    };
    let proposer_slashing = ProposerSlashing {
        signed_header_1: signed_header.clone(),
        signed_header_2: signed_header,
    };

    let attester_slashing = AttesterSlashing {
        attestation_1: indexed_attestation.clone(),
        attestation_2: indexed_attestation,
    };

    let attestation: Attestation<E> = Attestation {
        aggregation_bits: BitList::with_capacity(E::MaxValidatorsPerCommittee::to_usize()).unwrap(),
        data: AttestationData::default(),
        signature: AggregateSignature::empty(),
    };

    let deposit = Deposit {
        proof: FixedVector::from_elem(Hash256::from_low_u64_be(666 * seed)),
        data: deposit_data,
    };

    let voluntary_exit = VoluntaryExit {
        epoch: Epoch::new(1),
        validator_index: 1,
    };

    let signed_voluntary_exit = SignedVoluntaryExit {
        message: voluntary_exit,
        signature: Signature::empty(),
    };

    let mut block: BeaconBlock<E> = BeaconBlock::empty(spec);
    for _ in 0..E::MaxProposerSlashings::to_usize() {
        block
            .body
            .proposer_slashings
            .push(proposer_slashing.clone())
            .unwrap();
    }
    for _ in 0..E::MaxDeposits::to_usize() {
        block.body.deposits.push(deposit.clone()).unwrap();
    }
    for _ in 0..E::MaxVoluntaryExits::to_usize() {
        block
            .body
            .voluntary_exits
            .push(signed_voluntary_exit.clone())
            .unwrap();
    }
    for _ in 0..E::MaxAttesterSlashings::to_usize() {
        block
            .body
            .attester_slashings
            .push(attester_slashing.clone())
            .unwrap();
    }

    for _ in 0..E::MaxAttestations::to_usize() {
        block.body.attestations.push(attestation.clone()).unwrap();
    }
    block
}

pub fn get_attestation<E: EthSpec>(seed: u64) -> AttestationData {
    let slot = Slot::from(seed);
    let epoch = slot.epoch(E::slots_per_epoch());

    let build_checkpoint = |epoch_u64: u64| -> Checkpoint {
        Checkpoint {
            epoch: Epoch::new(epoch_u64),
            root: Hash256::from_low_u64_be(333 * seed),
        }
    };

    let source = build_checkpoint(epoch.as_u64().saturating_sub(2));
    let target = build_checkpoint(epoch.as_u64());

    let index = 0xc137u64;

    AttestationData {
        slot,
        index,
        beacon_block_root: Hash256::from_low_u64_be(666 * seed),
        source,
        target,
    }
}
