use crate::*;
use remote_signer_consumer::RemoteSignerObject;
use std::marker::PhantomData;
use types::{AttestationData, BeaconBlock, Domain, Epoch, EthSpec, Fork, Hash256};

pub struct RemoteSignerTestData<E: EthSpec, T: RemoteSignerObject> {
    pub public_key: String,
    pub bls_domain: Domain,
    pub data: T,
    pub fork: Fork,
    pub genesis_validators_root: Hash256,

    _phantom: PhantomData<E>,
}

impl<'a, E: EthSpec, T: RemoteSignerObject> RemoteSignerTestData<E, T> {
    pub fn new(public_key: &str, data: T, bls_domain: Domain) -> Self {
        let epoch = data.get_epoch();

        Self {
            public_key: public_key.to_string(),
            bls_domain,
            data,
            fork: Fork {
                previous_version: [1; 4],
                current_version: [2; 4],
                epoch,
            },
            genesis_validators_root: Hash256::from_low_u64_be(0xc137),

            _phantom: PhantomData,
        }
    }
}

pub fn get_input_data_block(seed: u64) -> RemoteSignerTestData<E, BeaconBlock<E>> {
    let block = get_block::<E>(seed);
    RemoteSignerTestData::new(PUBLIC_KEY_1, block, Domain::BeaconProposer)
}

pub fn get_input_data_attestation(seed: u64) -> RemoteSignerTestData<E, AttestationData> {
    let attestation = get_attestation::<E>(seed);
    RemoteSignerTestData::new(PUBLIC_KEY_1, attestation, Domain::BeaconAttester)
}

pub fn get_input_data_randao(seed: u64) -> RemoteSignerTestData<E, Epoch> {
    let epoch = Epoch::new(seed);
    RemoteSignerTestData::new(PUBLIC_KEY_1, epoch, Domain::Randao)
}

pub fn get_input_data_and_set_domain<E: EthSpec, T: RemoteSignerObject>(
    f: fn(u64) -> RemoteSignerTestData<E, T>,
    bls_domain: Domain,
) -> RemoteSignerTestData<E, T> {
    let mut test_input = f(0xc137);
    test_input.bls_domain = bls_domain;

    test_input
}

pub fn get_input_data_and_set_public_key<E: EthSpec, T: RemoteSignerObject>(
    f: fn(u64) -> RemoteSignerTestData<E, T>,
    p: &str,
) -> RemoteSignerTestData<E, T> {
    let mut test_input = f(0xc137);
    test_input.public_key = p.to_string();

    test_input
}
