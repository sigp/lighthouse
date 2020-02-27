use crate::errors::BeaconChainError;
use std::collections::HashMap;
use types::{BeaconState, EthSpec, PublicKey, PublicKeyBytes, Validator};

pub struct ValidatorPubkeyCache {
    pubkeys: Vec<PublicKey>,
    indices: HashMap<PublicKeyBytes, usize>,
}

impl ValidatorPubkeyCache {
    pub fn new<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, BeaconChainError> {
        let mut cache = Self {
            pubkeys: vec![],
            indices: HashMap::new(),
        };

        cache.import(&state.validators)?;

        Ok(cache)
    }

    pub fn import_new_pubkeys<T: EthSpec>(
        &mut self,
        state: &BeaconState<T>,
    ) -> Result<(), BeaconChainError> {
        if state.validators.len() > self.pubkeys.len() {
            self.import(&state.validators[self.pubkeys.len()..])
        } else {
            Ok(())
        }
    }

    fn import(&mut self, validators: &[Validator]) -> Result<(), BeaconChainError> {
        self.pubkeys.reserve(validators.len());
        self.indices.reserve(validators.len());

        for v in validators.iter() {
            let i = self.pubkeys.len();
            self.pubkeys.push(
                v.pubkey
                    .decompress()
                    .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?,
            );
            self.indices.insert(v.pubkey.clone(), i);
        }

        Ok(())
    }

    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
    }

    pub fn get_index(&self, pubkey: &PublicKeyBytes) -> Option<usize> {
        self.indices.get(pubkey).copied()
    }
}
