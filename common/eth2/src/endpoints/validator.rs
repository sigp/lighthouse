//! Validator API endpoints.

use crate::client::{BeaconNodeHttpClient, Error, V1, V2, V3};
use crate::types::*;
use reqwest::{StatusCode, Url};
use types::EthSpec;

impl BeaconNodeHttpClient {
    // ===============================
    // Sync Committee & Contribution Management
    // ===============================

    /// `POST validator/contribution_and_proofs`
    pub async fn post_validator_contribution_and_proofs<E: EthSpec>(
        &self,
        signed_contributions: &[SignedContributionAndProof<E>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("contribution_and_proofs");

        self.post_with_timeout(
            path,
            &signed_contributions,
            self.timeouts().sync_committee_contribution,
        )
        .await?;

        Ok(())
    }

    /// `GET validator/sync_committee_contribution`
    pub async fn get_validator_sync_committee_contribution<E: EthSpec>(
        &self,
        sync_committee_data: &SyncContributionData,
    ) -> Result<Option<GenericResponse<SyncCommitteeContribution<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("sync_committee_contribution");

        path.query_pairs_mut()
            .append_pair("slot", &sync_committee_data.slot.to_string())
            .append_pair(
                "beacon_block_root",
                &format!("{:?}", sync_committee_data.beacon_block_root),
            )
            .append_pair(
                "subcommittee_index",
                &sync_committee_data.subcommittee_index.to_string(),
            );

        self.get_opt(path).await
    }

    /// `POST validator/sync_committee_subscriptions`
    pub async fn post_validator_sync_committee_subscriptions(
        &self,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("sync_committee_subscriptions");

        self.post(path, &subscriptions).await?;

        Ok(())
    }

    // ===============================
    // Beacon Proposer Management
    // ===============================

    /// `POST validator/prepare_beacon_proposer`
    pub async fn post_validator_prepare_beacon_proposer(
        &self,
        preparation_data: &[ProposerPreparationData],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("prepare_beacon_proposer");

        self.post(path, &preparation_data).await?;

        Ok(())
    }

    /// `POST validator/register_validator`
    pub async fn post_validator_register_validator(
        &self,
        registration_data: &[SignedValidatorRegistrationData],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("register_validator");

        self.post(path, &registration_data).await?;

        Ok(())
    }

    // ===============================
    // Validator Duties
    // ===============================

    /// `GET validator/duties/proposer/{epoch}`
    pub async fn get_validator_duties_proposer(
        &self,
        epoch: Epoch,
    ) -> Result<DutiesResponse<Vec<ProposerData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("duties")
            .push("proposer")
            .push(&epoch.to_string());

        self.get_with_timeout(path, self.timeouts().proposer_duties)
            .await
    }

    /// `POST validator/duties/attester/{epoch}`
    pub async fn post_validator_duties_attester(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<DutiesResponse<Vec<AttesterData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("duties")
            .push("attester")
            .push(&epoch.to_string());

        self.post_with_timeout_and_response(
            path,
            &ValidatorIndexDataRef(indices),
            self.timeouts().attester_duties,
        )
        .await
    }

    /// `POST validator/duties/sync/{epoch}`
    pub async fn post_validator_duties_sync(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<ExecutionOptimisticFinalizedResponse<Vec<SyncDuty>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("duties")
            .push("sync")
            .push(&epoch.to_string());

        self.post_with_timeout_and_response(
            path,
            &ValidatorIndexDataRef(indices),
            self.timeouts().sync_duties,
        )
        .await
    }

    // ===============================
    // Block Production (V2 API)
    // ===============================

    /// `GET v2/validator/blocks/{slot}`
    pub async fn get_validator_blocks<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<ForkVersionedResponse<FullBlockContents<E>>, Error> {
        self.get_validator_blocks_modular(slot, randao_reveal, graffiti, SkipRandaoVerification::No)
            .await
    }

    /// `GET v2/validator/blocks/{slot}`
    pub async fn get_validator_blocks_modular<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<ForkVersionedResponse<FullBlockContents<E>>, Error> {
        let path = self
            .get_validator_blocks_path::<E>(slot, randao_reveal, graffiti, skip_randao_verification)
            .await?;

        self.get(path).await
    }

    /// returns `GET v2/validator/blocks/{slot}` URL path
    pub async fn get_validator_blocks_path<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("blocks")
            .push(&slot.to_string());

        path.query_pairs_mut()
            .append_pair("randao_reveal", &randao_reveal.to_string());

        if let Some(graffiti) = graffiti {
            path.query_pairs_mut()
                .append_pair("graffiti", &graffiti.to_string());
        }

        if skip_randao_verification == SkipRandaoVerification::Yes {
            path.query_pairs_mut()
                .append_pair("skip_randao_verification", "");
        }

        Ok(path)
    }

    /// `GET v2/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.get_validator_blocks_modular_ssz::<E>(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
        )
        .await
    }

    /// `GET v2/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_modular_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Option<Vec<u8>>, Error> {
        let path = self
            .get_validator_blocks_path::<E>(slot, randao_reveal, graffiti, skip_randao_verification)
            .await?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts().get_validator_block)
            .await
    }

    // ===============================
    // Block Production (V3 API)
    // ===============================

    /// returns `GET v3/validator/blocks/{slot}` URL path
    pub async fn get_validator_blocks_v3_path(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
        builder_booster_factor: Option<u64>,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V3)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("blocks")
            .push(&slot.to_string());

        path.query_pairs_mut()
            .append_pair("randao_reveal", &randao_reveal.to_string());

        if let Some(graffiti) = graffiti {
            path.query_pairs_mut()
                .append_pair("graffiti", &graffiti.to_string());
        }

        if skip_randao_verification == SkipRandaoVerification::Yes {
            path.query_pairs_mut()
                .append_pair("skip_randao_verification", "");
        }

        if let Some(builder_booster_factor) = builder_booster_factor {
            path.query_pairs_mut()
                .append_pair("builder_boost_factor", &builder_booster_factor.to_string());
        }

        Ok(path)
    }

    /// `GET v3/validator/blocks/{slot}`
    pub async fn get_validator_blocks_v3<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        builder_booster_factor: Option<u64>,
    ) -> Result<(JsonProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        self.get_validator_blocks_v3_modular(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
            builder_booster_factor,
        )
        .await
    }

    /// `GET v3/validator/blocks/{slot}`
    pub async fn get_validator_blocks_v3_modular<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
        builder_booster_factor: Option<u64>,
    ) -> Result<(JsonProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        let path = self
            .get_validator_blocks_v3_path(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
                builder_booster_factor,
            )
            .await?;

        let opt_result = self
            .get_response_with_response_headers(
                path,
                Accept::Json,
                self.timeouts().get_validator_block,
                |response, headers| async move {
                    let header_metadata = ProduceBlockV3Metadata::try_from(&headers)
                        .map_err(Error::InvalidHeaders)?;
                    if header_metadata.execution_payload_blinded {
                        let blinded_response = response
                            .json::<ForkVersionedResponse<BlindedBeaconBlock<E>, ProduceBlockV3Metadata>>()
                            .await?
                            .map_data(ProduceBlockV3Response::Blinded);
                        Ok((blinded_response, header_metadata))
                    } else {
                        let full_block_response = response
                            .json::<ForkVersionedResponse<FullBlockContents<E>, ProduceBlockV3Metadata>>()
                            .await?
                            .map_data(ProduceBlockV3Response::Full);
                        Ok((full_block_response, header_metadata))
                    }
                },
            )
            .await?;

        // Generic handler is optional but this route should never 404 unless unimplemented
        opt_result.ok_or(Error::StatusCode(StatusCode::NOT_FOUND))
    }

    /// `GET v3/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_v3_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        builder_booster_factor: Option<u64>,
    ) -> Result<(ProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        self.get_validator_blocks_v3_modular_ssz::<E>(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
            builder_booster_factor,
        )
        .await
    }

    /// `GET v3/validator/blocks/{slot}` in ssz format
    pub async fn get_validator_blocks_v3_modular_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
        builder_booster_factor: Option<u64>,
    ) -> Result<(ProduceBlockV3Response<E>, ProduceBlockV3Metadata), Error> {
        let path = self
            .get_validator_blocks_v3_path(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
                builder_booster_factor,
            )
            .await?;

        let opt_response = self
            .get_response_with_response_headers(
                path,
                Accept::Ssz,
                self.timeouts().get_validator_block,
                |response, headers| async move {
                    let metadata = ProduceBlockV3Metadata::try_from(&headers)
                        .map_err(Error::InvalidHeaders)?;
                    let response_bytes = response.bytes().await?;

                    // Parse bytes based on metadata.
                    let response = if metadata.execution_payload_blinded {
                        ProduceBlockV3Response::Blinded(
                            BlindedBeaconBlock::from_ssz_bytes_for_fork(
                                &response_bytes,
                                metadata.consensus_version,
                            )
                            .map_err(Error::InvalidSsz)?,
                        )
                    } else {
                        ProduceBlockV3Response::Full(
                            FullBlockContents::from_ssz_bytes_for_fork(
                                &response_bytes,
                                metadata.consensus_version,
                            )
                            .map_err(Error::InvalidSsz)?,
                        )
                    };

                    Ok((response, metadata))
                },
            )
            .await?;

        // Generic handler is optional but this route should never 404 unless unimplemented
        opt_response.ok_or(Error::StatusCode(StatusCode::NOT_FOUND))
    }

    // ===============================
    // Blinded Block Production
    // ===============================

    /// `GET v1/validator/blinded_blocks/{slot}`
    pub async fn get_validator_blinded_blocks<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<ForkVersionedResponse<BlindedBeaconBlock<E>>, Error> {
        self.get_validator_blinded_blocks_modular(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
        )
        .await
    }

    /// returns `GET v1/validator/blinded_blocks/{slot}` URL path
    pub async fn get_validator_blinded_blocks_path<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("blinded_blocks")
            .push(&slot.to_string());

        path.query_pairs_mut()
            .append_pair("randao_reveal", &randao_reveal.to_string());

        if let Some(graffiti) = graffiti {
            path.query_pairs_mut()
                .append_pair("graffiti", &graffiti.to_string());
        }

        if skip_randao_verification == SkipRandaoVerification::Yes {
            path.query_pairs_mut()
                .append_key_only("skip_randao_verification");
        }

        Ok(path)
    }

    /// `GET v1/validator/blinded_blocks/{slot}`
    pub async fn get_validator_blinded_blocks_modular<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<ForkVersionedResponse<BlindedBeaconBlock<E>>, Error> {
        let path = self
            .get_validator_blinded_blocks_path::<E>(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
            )
            .await?;

        self.get(path).await
    }

    /// `GET v1/validator/blinded_blocks/{slot}` in ssz format
    pub async fn get_validator_blinded_blocks_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.get_validator_blinded_blocks_modular_ssz::<E>(
            slot,
            randao_reveal,
            graffiti,
            SkipRandaoVerification::No,
        )
        .await
    }

    pub async fn get_validator_blinded_blocks_modular_ssz<E: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &SignatureBytes,
        graffiti: Option<&Graffiti>,
        skip_randao_verification: SkipRandaoVerification,
    ) -> Result<Option<Vec<u8>>, Error> {
        let path = self
            .get_validator_blinded_blocks_path::<E>(
                slot,
                randao_reveal,
                graffiti,
                skip_randao_verification,
            )
            .await?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts().get_validator_block)
            .await
    }

    // ===============================
    // Attestation Management
    // ===============================

    /// `GET validator/attestation_data?slot,committee_index`
    pub async fn get_validator_attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<GenericResponse<AttestationData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("attestation_data");

        path.query_pairs_mut()
            .append_pair("slot", &slot.to_string())
            .append_pair("committee_index", &committee_index.to_string());

        self.get_with_timeout(path, self.timeouts().attestation).await
    }

    /// `GET v1/validator/aggregate_attestation?slot,attestation_data_root`
    pub async fn get_validator_aggregate_attestation_v1<E: EthSpec>(
        &self,
        slot: Slot,
        attestation_data_root: Hash256,
    ) -> Result<Option<GenericResponse<Attestation<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("aggregate_attestation");

        path.query_pairs_mut()
            .append_pair("slot", &slot.to_string())
            .append_pair(
                "attestation_data_root",
                &format!("{:?}", attestation_data_root),
            );

        self.get_opt_with_timeout(path, self.timeouts().attestation)
            .await
    }

    /// `GET v2/validator/aggregate_attestation?slot,attestation_data_root,committee_index`
    pub async fn get_validator_aggregate_attestation_v2<E: EthSpec>(
        &self,
        slot: Slot,
        attestation_data_root: Hash256,
        committee_index: CommitteeIndex,
    ) -> Result<Option<ForkVersionedResponse<Attestation<E>>>, Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("aggregate_attestation");

        path.query_pairs_mut()
            .append_pair("slot", &slot.to_string())
            .append_pair(
                "attestation_data_root",
                &format!("{:?}", attestation_data_root),
            )
            .append_pair("committee_index", &committee_index.to_string());

        self.get_opt_with_timeout(path, self.timeouts().attestation)
            .await
    }

    /// `POST v1/validator/aggregate_and_proofs`
    pub async fn post_validator_aggregate_and_proof_v1<E: EthSpec>(
        &self,
        aggregates: &[SignedAggregateAndProof<E>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("aggregate_and_proofs");

        self.post_with_timeout(path, &aggregates, self.timeouts().attestation)
            .await?;

        Ok(())
    }

    /// `POST v2/validator/aggregate_and_proofs`
    pub async fn post_validator_aggregate_and_proof_v2<E: EthSpec>(
        &self,
        aggregates: &[SignedAggregateAndProof<E>],
        fork_name: ForkName,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("aggregate_and_proofs");

        self.post_with_timeout_and_consensus_header(
            path,
            &aggregates,
            self.timeouts().attestation,
            fork_name,
        )
        .await?;

        Ok(())
    }

    // ===============================
    // Committee Subscriptions
    // ===============================

    /// `POST validator/beacon_committee_subscriptions`
    pub async fn post_validator_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("beacon_committee_subscriptions");

        self.post_with_timeout(
            path,
            &subscriptions,
            self.timeouts().attestation_subscriptions,
        )
        .await?;

        Ok(())
    }

    // ===============================
    // Validator Liveness
    // ===============================

    /// `POST validator/liveness/{epoch}`
    pub async fn post_validator_liveness_epoch(
        &self,
        epoch: Epoch,
        indices: &[u64],
    ) -> Result<GenericResponse<Vec<StandardLivenessResponseData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("validator")
            .push("liveness")
            .push(&epoch.to_string());

        self.post_with_timeout_and_response(
            path,
            &ValidatorIndexDataRef(indices),
            self.timeouts().liveness,
        )
        .await
    }
}