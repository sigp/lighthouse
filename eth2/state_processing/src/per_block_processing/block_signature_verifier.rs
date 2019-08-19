use super::signature_sets::*;
use crate::common::get_indexed_attestation;
use crate::per_block_processing::errors::AttestationValidationError;
use bls::{verify_signature_sets, SignatureSet};
use types::{BeaconBlock, BeaconState, ChainSpec, EthSpec, IndexedAttestation};

/// Reads the BLS signatures and keys from a `BeaconBlock`, storing them as a `Vec<SignatureSet>`.
///
/// This allows for optimizations related to batch BLS operations (see the
/// `Self::verify_entire_block(..)` function).
pub struct BlockSignatureVerifier<'a, T: EthSpec> {
    block: &'a BeaconBlock<T>,
    state: &'a BeaconState<T>,
    spec: &'a ChainSpec,
    sets: Vec<SignatureSet<'a>>,
}

impl<'a, T: EthSpec> BlockSignatureVerifier<'a, T> {
    fn new(state: &'a BeaconState<T>, block: &'a BeaconBlock<T>, spec: &'a ChainSpec) -> Self {
        Self {
            block,
            state,
            spec,
            sets: vec![],
        }
    }

    /// Verify all* the signatures in the given `BeaconBlock`, returning `Ok(())` if the signatures
    /// are valid.
    ///
    /// * : _Does not verify any signatures in `block.body.deposits`. A block is still valid if it
    /// contains invalid signatures on deposits._
    ///
    /// ## Notes
    ///
    /// Signature validation will take place in accordance to the [Faster verification of multiple
    /// BLS signatures](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407)
    /// optimization proposed by Vitalik Buterin.
    ///
    /// It is not possible to know exactly _which_ signature is invalid here, just that
    /// _at least one_ was invalid.
    pub fn verify_entire_block(
        state: &'a BeaconState<T>,
        block: &'a BeaconBlock<T>,
        spec: &'a ChainSpec,
    ) -> Result<()> {
        let mut verifier = Self::new(state, block, spec);

        verifier.include_block_proposal()?;
        verifier.include_randao_reveal()?;
        verifier.include_proposer_slashings()?;

        // ## Attestation signatures
        //
        let attester_slashing_aggregate_public_keys =
            verifier.produce_attester_slashings_aggregate_public_keys()?;
        verifier.include_attester_slashing_indexed_attestations(
            &attester_slashing_aggregate_public_keys,
        )?;

        // ## Attestation signatures
        //
        // Map `block.body.attestations` to `IndexedAttestations`, then produce the respective `AggregatePublicKeys`
        //  and add the signature sets to `s`.
        //
        // The reason for the 3-step process for attestation verification is to ensure that the
        // `Signature` from `IndexedAttestation` and the newly-created `AggregatePublicKey` can
        // live long enough.
        let indexed_attestations = verifier.produce_indexed_attestations()?;
        let indexed_attestation_aggregate_public_keys =
            verifier.produce_indexed_attestation_aggregate_public_keys(&indexed_attestations)?;
        verifier.include_indexed_attestations(
            &indexed_attestations,
            &indexed_attestation_aggregate_public_keys,
        )?;

        /*
         * Deposits are not included because they can potentially have invalid signatures.
         *
         *
        // ## Deposit signatures
        //
        // Collect all the valid pubkeys, signatures and messages from the block, then include them
        // in `s`.
        //
        // Deposits with invalid pubkeys/signatures are simply ignored here. It is important to
        // ensure that the downstream function checks again to ensure a validators key/sig is
        // valid. Otherwise, it may be possible to induct validators with invalid keys/sigs.
        let deposit_pubkeys_signatures_messages = verifier.produce_deposit_pubkeys_and_signatures();
        verifier.include_deposits(&deposit_pubkeys_signatures_messages)?;
        */

        verifier.include_exits()?;
        verifier.include_transfers()?;

        if verify_signature_sets(verifier.into_iter()) {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }

    fn include_block_proposal(&mut self) -> Result<()> {
        let set = block_proposal_signature_set(self.state, self.block, self.spec)?;
        self.sets.push(set);
        Ok(())
    }

    fn include_randao_reveal(&mut self) -> Result<()> {
        let set = randao_signature_set(self.state, self.block, self.spec)?;
        self.sets.push(set);
        Ok(())
    }

    fn include_proposer_slashings(&mut self) -> Result<()> {
        let mut sets: Vec<SignatureSet> = self
            .block
            .body
            .proposer_slashings
            .iter()
            .map(|proposer_slashing| {
                proposer_slashing_signature_set(self.state, proposer_slashing, self.spec)
                    .map(|a| a.to_vec())
            })
            .collect::<Result<Vec<Vec<SignatureSet>>>>()?
            .iter()
            .flatten()
            .cloned()
            .collect();

        self.sets.append(&mut sets);
        Ok(())
    }

    fn produce_attester_slashings_aggregate_public_keys(
        &self,
    ) -> Result<Vec<AttesterSlashingPublicKeys>> {
        self.block
            .body
            .attester_slashings
            .iter()
            .map(|attester_slashing| {
                Ok([
                    indexed_attestation_pubkeys(&self.state, &attester_slashing.attestation_1)?,
                    indexed_attestation_pubkeys(&self.state, &attester_slashing.attestation_2)?,
                ])
            })
            .collect::<Result<_>>()
    }

    fn include_attester_slashing_indexed_attestations(
        &mut self,
        attester_slashings_aggregate_public_keys: &'a [AttesterSlashingPublicKeys],
    ) -> Result<()> {
        let pubkey_len = attester_slashings_aggregate_public_keys.len();
        let other_len = self.block.body.attester_slashings.len();

        if pubkey_len != other_len {
            return Err(Error::MismatchedPublicKeyLen {
                pubkey_len,
                other_len,
            });
        }

        let mut sets: Vec<SignatureSet> = self
            .block
            .body
            .attester_slashings
            .iter()
            .zip(attester_slashings_aggregate_public_keys)
            .map(|(attester_slashing, public_keys)| {
                attester_slashing_signature_set(
                    &self.state,
                    &attester_slashing,
                    public_keys,
                    &self.spec,
                )
                .map(|set| set.to_vec())
            })
            .collect::<Result<Vec<Vec<SignatureSet>>>>()?
            .iter()
            .flatten()
            .cloned()
            .collect();

        self.sets.append(&mut sets);

        Ok(())
    }

    fn produce_indexed_attestations(&mut self) -> Result<Vec<IndexedAttestation<T>>> {
        self.block
            .body
            .attestations
            .iter()
            .map(|attestation| get_indexed_attestation(self.state, attestation))
            .collect::<std::result::Result<Vec<IndexedAttestation<T>>, AttestationValidationError>>(
            )
            .map_err(Into::into)
    }

    fn produce_indexed_attestation_aggregate_public_keys(
        &mut self,
        indexed_attestations: &'a [IndexedAttestation<T>],
    ) -> Result<Vec<IndexedAttestationPublicKeys>> {
        indexed_attestations
            .iter()
            .map(|indexed_attestation| indexed_attestation_pubkeys(self.state, indexed_attestation))
            .collect::<Result<_>>()
    }

    fn include_indexed_attestations(
        &mut self,
        indexed_attestations: &'a [IndexedAttestation<T>],
        indexed_attestation_aggregate_public_keys: &'a [IndexedAttestationPublicKeys],
    ) -> Result<()> {
        let pubkey_len = indexed_attestation_aggregate_public_keys.len();
        let other_len = self.block.body.attestations.len();

        if pubkey_len != other_len {
            return Err(Error::MismatchedPublicKeyLen {
                pubkey_len,
                other_len,
            });
        }

        let mut sets: Vec<SignatureSet> = indexed_attestations
            .into_iter()
            .zip(indexed_attestation_aggregate_public_keys)
            .map(|(indexed_attestation, pubkeys)| {
                indexed_attestation_signature_set(
                    self.state,
                    indexed_attestation,
                    pubkeys,
                    self.spec,
                )
            })
            .collect::<Result<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }

    /* Invalid deposits keys/sigs in Deposits are permitted. This code is not needed.
     *
     *
    fn produce_deposit_pubkeys_and_signatures(&mut self) -> Vec<(PublicKey, Signature, Message)> {
        deposit_pubkeys_signatures_messages(&self.block.body.deposits)
    }

    fn include_deposits(
        &mut self,
        pubkeys_signatures_messages: &'a [(PublicKey, Signature, Message)],
    ) -> Result<()> {
        let mut sets = pubkeys_signatures_messages
            .iter()
            .map(|pubkey_signature_message| {
                deposit_signature_set(&self.state, pubkey_signature_message, &self.spec)
            })
            .collect();

        self.sets.append(&mut sets);

        Ok(())
    }
    */

    fn include_exits(&mut self) -> Result<()> {
        let mut sets = self
            .block
            .body
            .voluntary_exits
            .iter()
            .map(|exit| exit_signature_set(&self.state, exit, &self.spec))
            .collect::<Result<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }

    fn include_transfers(&mut self) -> Result<()> {
        let mut sets = self
            .block
            .body
            .transfers
            .iter()
            .map(|transfer| transfer_signature_set(&self.state, transfer, &self.spec))
            .collect::<Result<_>>()?;

        self.sets.append(&mut sets);

        Ok(())
    }

    fn into_iter(self) -> impl Iterator<Item = SignatureSet<'a>> {
        self.sets.into_iter()
    }
}
