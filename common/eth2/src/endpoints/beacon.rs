//! Beacon chain API endpoints.

use crate::client::{BeaconNodeHttpClient, Error, V1, V2};
use crate::mixin::ResponseOptional;
use crate::types::*;
use either::Either;
use reqwest::{Response, Url};
use ssz::Encode;
use types::fork_versioned_response::ExecutionOptimisticFinalizedForkVersionedResponse;
use types::{ChainSpec, EthSpec};

impl BeaconNodeHttpClient {
    // ===============================
    // Genesis Endpoints
    // ===============================
    
    /// `GET beacon/genesis`
    ///
    /// ## Errors
    ///
    /// May return a `404` if beacon chain genesis has not yet occurred.
    pub async fn get_beacon_genesis(&self) -> Result<GenericResponse<GenesisData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("genesis");

        self.get(path).await
    }

    // ===============================
    // States Endpoints
    // ===============================

    /// `GET beacon/states/{state_id}/root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_root(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<RootData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("root");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/fork`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_fork(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Fork>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("fork");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/finality_checkpoints`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_finality_checkpoints(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<FinalityCheckpointsData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("finality_checkpoints");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/validator_balances?id`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validator_balances(
        &self,
        state_id: StateId,
        ids: Option<&[ValidatorId]>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorBalanceData>>>, Error>
    {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validator_balances");

        if let Some(ids) = ids {
            let id_string = ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("id", &id_string);
        }

        self.get_opt(path).await
    }

    /// TESTING ONLY: This request should fail with a 415 response code.
    pub async fn post_beacon_states_validator_balances_with_ssz_header(
        &self,
        state_id: StateId,
        ids: Vec<ValidatorId>,
    ) -> Result<Response, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validator_balances");

        let request = ValidatorBalancesRequestBody { ids };

        self.post_generic_with_ssz_header(path, &request).await
    }

    /// `POST beacon/states/{state_id}/validator_balances`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_states_validator_balances(
        &self,
        state_id: StateId,
        ids: Vec<ValidatorId>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorBalanceData>>>, Error>
    {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validator_balances");

        let request = ValidatorBalancesRequestBody { ids };

        self.post_with_opt_response(path, &request).await
    }

    /// `GET beacon/states/{state_id}/validators?id,status`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validators(
        &self,
        state_id: StateId,
        ids: Option<&[ValidatorId]>,
        statuses: Option<&[ValidatorStatus]>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validators");

        if let Some(ids) = ids {
            let id_string = ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("id", &id_string);
        }

        if let Some(statuses) = statuses {
            let status_string = statuses
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("status", &status_string);
        }

        self.get_opt(path).await
    }

    /// `POST beacon/states/{state_id}/validators`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_states_validators(
        &self,
        state_id: StateId,
        ids: Option<Vec<ValidatorId>>,
        statuses: Option<Vec<ValidatorStatus>>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<ValidatorData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validators");

        let request = ValidatorsRequestBody { ids, statuses };

        self.post_with_opt_response(path, &request).await
    }

    /// `GET beacon/states/{state_id}/committees?slot,index,epoch`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_committees(
        &self,
        state_id: StateId,
        slot: Option<Slot>,
        index: Option<u64>,
        epoch: Option<Epoch>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<CommitteeData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("committees");

        if let Some(slot) = slot {
            path.query_pairs_mut()
                .append_pair("slot", &slot.to_string());
        }

        if let Some(index) = index {
            path.query_pairs_mut()
                .append_pair("index", &index.to_string());
        }

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/sync_committees?epoch`
    pub async fn get_beacon_states_sync_committees(
        &self,
        state_id: StateId,
        epoch: Option<Epoch>,
    ) -> Result<ExecutionOptimisticFinalizedResponse<SyncCommitteeByValidatorIndices>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("sync_committees");

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.get(path).await
    }

    /// `GET beacon/states/{state_id}/randao?epoch`
    pub async fn get_beacon_states_randao(
        &self,
        state_id: StateId,
        epoch: Option<Epoch>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<RandaoMix>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("randao");

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/validators/{validator_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_validator_id(
        &self,
        state_id: StateId,
        validator_id: &ValidatorId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<ValidatorData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("validators")
            .push(&validator_id.to_string());

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/pending_deposits`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_pending_deposits(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<PendingDeposit>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("pending_deposits");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/pending_partial_withdrawals`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_pending_partial_withdrawals(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<PendingPartialWithdrawal>>>, Error>
    {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("pending_partial_withdrawals");

        self.get_opt(path).await
    }

    /// `GET beacon/states/{state_id}/pending_consolidations`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_states_pending_consolidations(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<PendingConsolidation>>>, Error>
    {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("pending_consolidations");

        self.get_opt(path).await
    }

    /// `GET beacon/deposit_snapshot`
    pub async fn get_deposit_snapshot(&self) -> Result<Option<types::DepositTreeSnapshot>, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("deposit_snapshot");
        self.get_opt_with_timeout::<GenericResponse<_>, _>(path, self.timeouts().get_deposit_snapshot)
            .await
            .map(|opt| opt.map(|r| r.data))
    }

    // ===============================
    // Light Client Endpoints
    // ===============================

    /// `GET beacon/light_client/updates`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_light_client_updates<E: EthSpec>(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Option<Vec<ForkVersionedResponse<LightClientUpdate<E>>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("light_client")
            .push("updates");

        path.query_pairs_mut()
            .append_pair("start_period", &start_period.to_string());

        path.query_pairs_mut()
            .append_pair("count", &count.to_string());

        self.get_opt(path).await
    }

    /// `GET beacon/light_client/optimistic_update`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_light_client_optimistic_update<E: EthSpec>(
        &self,
    ) -> Result<Option<ForkVersionedResponse<LightClientOptimisticUpdate<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("light_client")
            .push("optimistic_update");

        self.get_opt(path).await
    }

    /// `GET beacon/light_client/finality_update`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_light_client_finality_update<E: EthSpec>(
        &self,
    ) -> Result<Option<ForkVersionedResponse<LightClientFinalityUpdate<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("light_client")
            .push("finality_update");

        self.get_opt(path).await
    }

    // ===============================
    // Headers Endpoints
    // ===============================

    /// `GET beacon/headers?slot,parent_root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_headers(
        &self,
        slot: Option<Slot>,
        parent_root: Option<Hash256>,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<BlockHeaderData>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("headers");

        if let Some(slot) = slot {
            path.query_pairs_mut()
                .append_pair("slot", &slot.to_string());
        }

        if let Some(root) = parent_root {
            path.query_pairs_mut()
                .append_pair("parent_root", &format!("{:?}", root));
        }

        self.get_opt(path).await
    }

    /// `GET beacon/headers/{block_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_headers_block_id(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<BlockHeaderData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("headers")
            .push(&block_id.to_string());

        self.get_opt(path).await
    }

    // ===============================
    // Blocks Endpoints
    // ===============================

    /// `POST beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blocks<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blocks");

        self.post_with_timeout(path, block_contents, self.timeouts().proposal)
            .await?;

        Ok(())
    }

    /// `POST beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blocks_ssz<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blocks");

        self.post_generic_with_consensus_version_and_ssz_body(
            path,
            block_contents.as_ssz_bytes(),
            Some(self.timeouts().proposal),
            block_contents.signed_block().fork_name_unchecked(),
        )
        .await?;

        Ok(())
    }

    /// `POST beacon/blinded_blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blinded_blocks<E: EthSpec>(
        &self,
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blinded_blocks");

        self.post_with_timeout(path, block, self.timeouts().proposal)
            .await?;

        Ok(())
    }

    /// `POST beacon/blinded_blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn post_beacon_blinded_blocks_ssz<E: EthSpec>(
        &self,
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blinded_blocks");

        self.post_generic_with_consensus_version_and_ssz_body(
            path,
            block.as_ssz_bytes(),
            Some(self.timeouts().proposal),
            block.fork_name_unchecked(),
        )
        .await?;

        Ok(())
    }

    /// `POST v2/beacon/blocks`
    pub async fn post_beacon_blocks_v2<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version(
            self.post_beacon_blocks_v2_path(validation_level)?,
            block_contents,
            Some(self.timeouts().proposal),
            block_contents.signed_block().message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// `POST v2/beacon/blocks`
    pub async fn post_beacon_blocks_v2_ssz<E: EthSpec>(
        &self,
        block_contents: &PublishBlockRequest<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version_and_ssz_body(
            self.post_beacon_blocks_v2_path(validation_level)?,
            block_contents.as_ssz_bytes(),
            Some(self.timeouts().proposal),
            block_contents.signed_block().message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// `POST v2/beacon/blinded_blocks`
    pub async fn post_beacon_blinded_blocks_v2<E: EthSpec>(
        &self,
        signed_block: &SignedBlindedBeaconBlock<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version(
            self.post_beacon_blinded_blocks_v2_path(validation_level)?,
            signed_block,
            Some(self.timeouts().proposal),
            signed_block.message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// `POST v2/beacon/blinded_blocks`
    pub async fn post_beacon_blinded_blocks_v2_ssz<E: EthSpec>(
        &self,
        signed_block: &SignedBlindedBeaconBlock<E>,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<(), Error> {
        self.post_generic_with_consensus_version_and_ssz_body(
            self.post_beacon_blinded_blocks_v2_path(validation_level)?,
            signed_block.as_ssz_bytes(),
            Some(self.timeouts().proposal),
            signed_block.message().body().fork_name(),
        )
        .await?;

        Ok(())
    }

    /// `GET v2/beacon/blocks`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<
        Option<ExecutionOptimisticFinalizedForkVersionedResponse<SignedBeaconBlock<E>>>,
        Error,
    > {
        let path = self.get_beacon_blocks_path(block_id)?;
        let Some(response) = self.get_response(path, |b| b).await.optional()? else {
            return Ok(None);
        };

        Ok(Some(response.json().await?))
    }

    /// `GET v1/beacon/blinded_blocks/{block_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blinded_blocks<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<
        Option<ExecutionOptimisticFinalizedForkVersionedResponse<SignedBlindedBeaconBlock<E>>>,
        Error,
    > {
        let path = self.get_beacon_blinded_blocks_path(block_id)?;
        let Some(response) = self.get_response(path, |b| b).await.optional()? else {
            return Ok(None);
        };

        Ok(Some(response.json().await?))
    }

    /// `GET v1/beacon/blocks` (LEGACY)
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_v1<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ForkVersionedResponse<SignedBeaconBlock<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string());

        self.get_opt(path).await
    }

    /// `GET beacon/blocks` as SSZ
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_ssz<E: EthSpec>(
        &self,
        block_id: BlockId,
        spec: &ChainSpec,
    ) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        let path = self.get_beacon_blocks_path(block_id)?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts().get_beacon_blocks_ssz)
            .await?
            .map(|bytes| SignedBeaconBlock::from_ssz_bytes(bytes.as_slice(), spec).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `GET beacon/blinded_blocks/{block_id}` as SSZ
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blinded_blocks_ssz<E: EthSpec>(
        &self,
        block_id: BlockId,
        spec: &ChainSpec,
    ) -> Result<Option<SignedBlindedBeaconBlock<E>>, Error> {
        let path = self.get_beacon_blinded_blocks_path(block_id)?;

        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts().get_beacon_blocks_ssz)
            .await?
            .map(|bytes| {
                SignedBlindedBeaconBlock::from_ssz_bytes(bytes.as_slice(), spec).map_err(Error::InvalidSsz)
            })
            .transpose()
    }

    /// `GET beacon/blocks/{block_id}/root`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_root(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<RootData>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string())
            .push("root");

        self.get_opt(path).await
    }

    /// `GET v1/beacon/blocks/{block_id}/attestations`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_attestations_v1<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticFinalizedResponse<Vec<Attestation<E>>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string())
            .push("attestations");

        self.get_opt(path).await
    }

    /// `GET v2/beacon/blocks/{block_id}/attestations`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_beacon_blocks_attestations_v2<E: EthSpec>(
        &self,
        block_id: BlockId,
    ) -> Result<Option<ExecutionOptimisticFinalizedForkVersionedResponse<Vec<Attestation<E>>>>, Error>
    {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string())
            .push("attestations");

        self.get_opt(path).await
    }

    /// Path for `v1/beacon/blob_sidecars/{block_id}`
    pub fn get_blobs_path(&self, block_id: BlockId) -> Result<Url, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blob_sidecars")
            .push(&block_id.to_string());
        Ok(path)
    }

    /// `GET v1/beacon/blob_sidecars/{block_id}`
    ///
    /// Returns `Ok(None)` on a 404 error.
    pub async fn get_blobs<E: EthSpec>(
        &self,
        block_id: BlockId,
        indices: Option<&[u64]>,
    ) -> Result<Option<ExecutionOptimisticFinalizedForkVersionedResponse<BlobSidecarList<E>>>, Error>
    {
        let mut path = self.get_blobs_path(block_id)?;
        if let Some(indices) = indices {
            let indices_string = indices
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut()
                .append_pair("indices", &indices_string);
        }

        let Some(response) = self.get_response(path, |b| b).await.optional()? else {
            return Ok(None);
        };

        Ok(Some(response.json().await?))
    }

    /// Path for `v2/beacon/blocks` with broadcast validation
    pub fn post_beacon_blocks_v2_path(
        &self,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|_| Error::InvalidUrl(self.server().clone()))?
            .extend(&["beacon", "blocks"]);

        path.set_query(
            validation_level
                .map(|v| format!("broadcast_validation={}", v))
                .as_deref(),
        );

        Ok(path)
    }

    /// Path for `v2/beacon/blinded_blocks` with broadcast validation
    pub fn post_beacon_blinded_blocks_v2_path(
        &self,
        validation_level: Option<BroadcastValidation>,
    ) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|_| Error::InvalidUrl(self.server().clone()))?
            .extend(&["beacon", "blinded_blocks"]);

        path.set_query(
            validation_level
                .map(|v| format!("broadcast_validation={}", v))
                .as_deref(),
        );

        Ok(path)
    }

    /// Path for `v2/beacon/blocks/{block_id}`
    pub fn get_beacon_blocks_path(&self, block_id: BlockId) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string());
        Ok(path)
    }

    /// Path for `v1/beacon/blinded_blocks/{block_id}`
    pub fn get_beacon_blinded_blocks_path(&self, block_id: BlockId) -> Result<Url, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("blinded_blocks")
            .push(&block_id.to_string());
        Ok(path)
    }

    // ===============================
    // Pool Endpoints
    // ===============================

    /// `POST v1/beacon/pool/attestations`
    pub async fn post_beacon_pool_attestations_v1<E: EthSpec>(
        &self,
        attestations: &[Attestation<E>],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attestations");

        self.post_with_timeout(path, &attestations, self.timeouts().attestation)
            .await?;

        Ok(())
    }

    /// `POST v2/beacon/pool/attestations`
    pub async fn post_beacon_pool_attestations_v2<E: EthSpec>(
        &self,
        attestations: Either<Vec<Attestation<E>>, Vec<SingleAttestation>>,
        fork_name: ForkName,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attestations");

        match attestations {
            Either::Right(attestations) => {
                self.post_with_timeout_and_consensus_header(
                    path,
                    &attestations,
                    self.timeouts().attestation,
                    fork_name,
                )
                .await?;
            }
            Either::Left(attestations) => {
                self.post_with_timeout_and_consensus_header(
                    path,
                    &attestations,
                    self.timeouts().attestation,
                    fork_name,
                )
                .await?;
            }
        };

        Ok(())
    }

    /// `GET v1/beacon/pool/attestations?slot,committee_index`
    pub async fn get_beacon_pool_attestations_v1<E: EthSpec>(
        &self,
        slot: Option<Slot>,
        committee_index: Option<u64>,
    ) -> Result<GenericResponse<Vec<Attestation<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attestations");

        if let Some(slot) = slot {
            path.query_pairs_mut()
                .append_pair("slot", &slot.to_string());
        }

        if let Some(index) = committee_index {
            path.query_pairs_mut()
                .append_pair("committee_index", &index.to_string());
        }

        self.get(path).await
    }

    /// `GET v2/beacon/pool/attestations?slot,committee_index`
    pub async fn get_beacon_pool_attestations_v2<E: EthSpec>(
        &self,
        slot: Option<Slot>,
        committee_index: Option<u64>,
    ) -> Result<ForkVersionedResponse<Vec<Attestation<E>>>, Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attestations");

        if let Some(slot) = slot {
            path.query_pairs_mut()
                .append_pair("slot", &slot.to_string());
        }

        if let Some(index) = committee_index {
            path.query_pairs_mut()
                .append_pair("committee_index", &index.to_string());
        }

        self.get(path).await
    }

    /// `POST v1/beacon/pool/attester_slashings`
    pub async fn post_beacon_pool_attester_slashings_v1<E: EthSpec>(
        &self,
        slashing: &AttesterSlashing<E>,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attester_slashings");

        self.post_generic(path, slashing, None).await?;

        Ok(())
    }

    /// `POST v2/beacon/pool/attester_slashings`
    pub async fn post_beacon_pool_attester_slashings_v2<E: EthSpec>(
        &self,
        slashing: &AttesterSlashing<E>,
        fork_name: ForkName,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attester_slashings");

        self.post_generic_with_consensus_version(path, slashing, None, fork_name)
            .await?;

        Ok(())
    }

    /// `GET v1/beacon/pool/attester_slashings`
    pub async fn get_beacon_pool_attester_slashings_v1<E: EthSpec>(
        &self,
    ) -> Result<GenericResponse<Vec<AttesterSlashing<E>>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attester_slashings");

        self.get(path).await
    }

    /// `GET v2/beacon/pool/attester_slashings`
    pub async fn get_beacon_pool_attester_slashings_v2<E: EthSpec>(
        &self,
    ) -> Result<ForkVersionedResponse<Vec<AttesterSlashing<E>>>, Error> {
        let mut path = self.eth_path(V2)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("attester_slashings");

        self.get(path).await
    }

    /// `POST beacon/pool/proposer_slashings`
    pub async fn post_beacon_pool_proposer_slashings(
        &self,
        slashing: &ProposerSlashing,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("proposer_slashings");

        self.post(path, slashing).await?;

        Ok(())
    }

    /// `GET beacon/pool/proposer_slashings`
    pub async fn get_beacon_pool_proposer_slashings(
        &self,
    ) -> Result<GenericResponse<Vec<ProposerSlashing>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("proposer_slashings");

        self.get(path).await
    }

    /// `POST beacon/pool/voluntary_exits`
    pub async fn post_beacon_pool_voluntary_exits(
        &self,
        exit: &SignedVoluntaryExit,
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("voluntary_exits");

        self.post(path, exit).await?;

        Ok(())
    }

    /// `GET beacon/pool/voluntary_exits`
    pub async fn get_beacon_pool_voluntary_exits(
        &self,
    ) -> Result<GenericResponse<Vec<SignedVoluntaryExit>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("voluntary_exits");

        self.get(path).await
    }

    /// `POST beacon/pool/sync_committees`
    pub async fn post_beacon_pool_sync_committee_signatures(
        &self,
        signatures: &[SyncCommitteeMessage],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("sync_committees");

        self.post(path, &signatures).await?;

        Ok(())
    }

    /// `POST beacon/pool/bls_to_execution_changes`
    pub async fn post_beacon_pool_bls_to_execution_changes(
        &self,
        address_changes: &[SignedBlsToExecutionChange],
    ) -> Result<(), Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("pool")
            .push("bls_to_execution_changes");

        self.post(path, &address_changes).await?;

        Ok(())
    }

    // ===============================
    // Builder API Endpoints
    // ===============================

    /// `GET builder/states/{state_id}/expected_withdrawals`
    pub async fn get_expected_withdrawals(
        &self,
        state_id: &StateId,
    ) -> Result<ExecutionOptimisticFinalizedResponse<Vec<Withdrawal>>, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("builder")
            .push("states")
            .push(&state_id.to_string())
            .push("expected_withdrawals");
        self.get(path).await
    }

    // ===============================
    // Rewards Endpoints
    // ===============================

    /// `POST beacon/rewards/sync_committee`
    pub async fn post_beacon_rewards_sync_committee(
        &self,
        block_id: BlockId,
        validators: &[ValidatorId],
    ) -> Result<GenericResponse<Vec<SyncCommitteeReward>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("rewards")
            .push("sync_committee")
            .push(&block_id.to_string());

        self.post_with_response(path, &validators).await
    }

    /// `GET beacon/rewards/blocks`
    pub async fn get_beacon_rewards_blocks(
        &self,
        block_id: BlockId,
    ) -> Result<GenericResponse<StandardBlockReward>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("rewards")
            .push("blocks")
            .push(&block_id.to_string());

        self.get(path).await
    }

    /// `POST beacon/rewards/attestations`
    pub async fn post_beacon_rewards_attestations(
        &self,
        epoch: Epoch,
        validators: &[ValidatorId],
    ) -> Result<StandardAttestationRewards, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("beacon")
            .push("rewards")
            .push("attestations")
            .push(&epoch.to_string());

        self.post_with_response(path, &validators).await
    }
}