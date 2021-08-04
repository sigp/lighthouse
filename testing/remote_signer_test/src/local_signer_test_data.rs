use crate::*;
use hex::decode;
use remote_signer_consumer::RemoteSignerObject;
use std::mem;
use types::{
    AttestationData, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, SecretKey,
    SignedRoot,
};

pub struct LocalSignerTestData<T: RemoteSignerObject> {
    secret_key: SecretKey,
    spec: ChainSpec,
    fork: Fork,
    genesis_validators_root: Hash256,
    obj: T,
}

impl<T: RemoteSignerObject> LocalSignerTestData<T> {
    pub fn new(obj: T) -> Self {
        let epoch = obj.get_epoch();

        Self {
            secret_key: SecretKey::deserialize(&decode(SECRET_KEY_1).unwrap()).unwrap(),
            spec: E::default_spec(),
            fork: Fork {
                previous_version: [1; 4],
                current_version: [2; 4],
                epoch,
            },
            genesis_validators_root: Hash256::from_low_u64_be(0xc137),
            obj,
        }
    }
}

impl LocalSignerTestData<BeaconBlock<E>> {
    pub fn sign(&self) -> String {
        let signed_block = self.obj.clone().sign(
            &self.secret_key,
            &self.fork,
            self.genesis_validators_root,
            &self.spec,
        );

        signed_block.signature().to_string()
    }
}

impl LocalSignerTestData<AttestationData> {
    pub fn sign(&self) -> String {
        let domain = self.spec.get_domain(
            self.obj.target.epoch,
            Domain::BeaconAttester,
            &self.fork,
            self.genesis_validators_root,
        );

        let message = self.obj.signing_root(domain);
        let signature = &self.secret_key.sign(message);

        signature.to_string()
    }
}

impl LocalSignerTestData<Epoch> {
    pub fn sign(&self) -> String {
        let domain = self.spec.get_domain(
            self.obj,
            Domain::Randao,
            &self.fork,
            self.genesis_validators_root,
        );

        let message = self.obj.signing_root(domain);
        let signature = &self.secret_key.sign(message);

        signature.to_string()
    }
}

pub fn get_input_local_signer_block(seed: u64) -> LocalSignerTestData<BeaconBlock<E>> {
    let block: BeaconBlock<E>;

    unsafe {
        block = mem::transmute(get_block::<E>(seed));
    }

    LocalSignerTestData::new(block)
}

pub fn get_input_local_signer_attestation(seed: u64) -> LocalSignerTestData<AttestationData> {
    let attestation: AttestationData;

    unsafe {
        attestation = mem::transmute(get_attestation::<E>(seed));
    }

    LocalSignerTestData::new(attestation)
}

pub fn get_input_local_signer_randao(seed: u64) -> LocalSignerTestData<Epoch> {
    LocalSignerTestData::new(Epoch::new(seed))
}
