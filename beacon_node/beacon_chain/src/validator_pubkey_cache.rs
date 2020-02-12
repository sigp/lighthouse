use crate::errors::BeaconChainError;
use std::convert::TryInto;
use types::{BeaconState, EthSpec, PublicKey};

pub struct ValidatorPubkeyCache {
    pubkeys: Vec<PublicKey>,
}

impl ValidatorPubkeyCache {
    pub fn new<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, BeaconChainError> {
        Ok(Self {
            pubkeys: state
                .validators
                .iter()
                .map(|v| {
                    (&v.pubkey)
                        .try_into()
                        .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)
                })
                .collect::<Result<Vec<_>, BeaconChainError>>()?,
        })
    }

    pub fn import_new_pubkeys<T: EthSpec>(
        &mut self,
        state: &BeaconState<T>,
    ) -> Result<(), BeaconChainError> {
        state
            .validators
            .iter()
            .skip(self.pubkeys.len())
            .try_for_each(|v| {
                self.pubkeys.push(
                    (&v.pubkey)
                        .try_into()
                        .map_err(BeaconChainError::InvalidValidatorPubkeyBytes)?,
                );
                Ok(())
            })
    }

    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
    }
}
