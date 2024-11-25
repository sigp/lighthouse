//! A collection of variables that are accessible outside of the network thread itself.
use crate::peer_manager::peerdb::PeerDB;
use crate::rpc::{MetaData, MetaDataV3};
use crate::types::{BackFillState, SyncState};
use crate::{Client, Enr, EnrExt, GossipTopic, Multiaddr, NetworkConfig, PeerId};
use itertools::Itertools;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use types::{ChainSpec, ColumnIndex, DataColumnSubnetId, EthSpec};

pub struct NetworkGlobals<E: EthSpec> {
    /// The current local ENR.
    pub local_enr: RwLock<Enr>,
    /// The local peer_id.
    pub peer_id: RwLock<PeerId>,
    /// Listening multiaddrs.
    pub listen_multiaddrs: RwLock<Vec<Multiaddr>>,
    /// The collection of known peers.
    pub peers: RwLock<PeerDB<E>>,
    // The local meta data of our node.
    pub local_metadata: RwLock<MetaData<E>>,
    /// The current gossipsub topic subscriptions.
    pub gossipsub_subscriptions: RwLock<HashSet<GossipTopic>>,
    /// The current sync status of the node.
    pub sync_state: RwLock<SyncState>,
    /// The current state of the backfill sync.
    pub backfill_state: RwLock<BackFillState>,
    /// The computed sampling subnets and columns is stored to avoid re-computing.
    pub sampling_subnets: Vec<DataColumnSubnetId>,
    pub sampling_columns: Vec<ColumnIndex>,
    /// Network-related configuration. Immutable after initialization.
    pub config: Arc<NetworkConfig>,
    /// Ethereum chain configuration. Immutable after initialization.
    pub spec: Arc<ChainSpec>,
}

impl<E: EthSpec> NetworkGlobals<E> {
    pub fn new(
        enr: Enr,
        local_metadata: MetaData<E>,
        trusted_peers: Vec<PeerId>,
        disable_peer_scoring: bool,
        log: &slog::Logger,
        config: Arc<NetworkConfig>,
        spec: Arc<ChainSpec>,
    ) -> Self {
        let (sampling_subnets, sampling_columns) = if spec.is_peer_das_scheduled() {
            let node_id = enr.node_id().raw();

            let custody_subnet_count = local_metadata
                .custody_subnet_count()
                .copied()
                .expect("custody subnet count must be set if PeerDAS is scheduled");

            let subnet_sampling_size = std::cmp::max(custody_subnet_count, spec.samples_per_slot);

            let sampling_subnets = DataColumnSubnetId::compute_custody_subnets::<E>(
                node_id,
                subnet_sampling_size,
                &spec,
            )
            .expect("sampling subnet count must be valid")
            .collect::<Vec<_>>();

            let sampling_columns = sampling_subnets
                .iter()
                .flat_map(|subnet| subnet.columns::<E>(&spec))
                .sorted()
                .collect();

            (sampling_subnets, sampling_columns)
        } else {
            (vec![], vec![])
        };

        NetworkGlobals {
            local_enr: RwLock::new(enr.clone()),
            peer_id: RwLock::new(enr.peer_id()),
            listen_multiaddrs: RwLock::new(Vec::new()),
            local_metadata: RwLock::new(local_metadata),
            peers: RwLock::new(PeerDB::new(trusted_peers, disable_peer_scoring, log)),
            gossipsub_subscriptions: RwLock::new(HashSet::new()),
            sync_state: RwLock::new(SyncState::Stalled),
            backfill_state: RwLock::new(BackFillState::Paused),
            sampling_subnets,
            sampling_columns,
            config,
            spec,
        }
    }

    /// Returns the local ENR from the underlying Discv5 behaviour that external peers may connect
    /// to.
    pub fn local_enr(&self) -> Enr {
        self.local_enr.read().clone()
    }

    /// Returns the local libp2p PeerID.
    pub fn local_peer_id(&self) -> PeerId {
        *self.peer_id.read()
    }

    /// Returns the list of `Multiaddr` that the underlying libp2p instance is listening on.
    pub fn listen_multiaddrs(&self) -> Vec<Multiaddr> {
        self.listen_multiaddrs.read().clone()
    }

    /// Returns the number of libp2p connected peers.
    pub fn connected_peers(&self) -> usize {
        self.peers.read().connected_peer_ids().count()
    }

    /// Returns the number of libp2p connected peers with outbound-only connections.
    pub fn connected_outbound_only_peers(&self) -> usize {
        self.peers.read().connected_outbound_only_peers().count()
    }

    /// Returns the number of libp2p peers that are either connected or being dialed.
    pub fn connected_or_dialing_peers(&self) -> usize {
        self.peers.read().connected_or_dialing_peers().count()
    }

    /// Returns in the node is syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync_state.read().is_syncing()
    }

    /// Returns the current sync state of the peer.
    pub fn sync_state(&self) -> SyncState {
        self.sync_state.read().clone()
    }

    /// Returns the current backfill state.
    pub fn backfill_state(&self) -> BackFillState {
        self.backfill_state.read().clone()
    }

    /// Returns a `Client` type if one is known for the `PeerId`.
    pub fn client(&self, peer_id: &PeerId) -> Client {
        self.peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client().clone())
            .unwrap_or_default()
    }

    /// Updates the syncing state of the node.
    ///
    /// The old state is returned
    pub fn set_sync_state(&self, new_state: SyncState) -> SyncState {
        std::mem::replace(&mut *self.sync_state.write(), new_state)
    }

    /// Returns a connected peer that:
    /// 1. is connected
    /// 2. assigned to custody the column based on it's `custody_subnet_count` from ENR or metadata
    /// 3. has a good score
    pub fn custody_peers_for_column(&self, column_index: ColumnIndex) -> Vec<PeerId> {
        self.peers
            .read()
            .good_custody_subnet_peer(DataColumnSubnetId::from_column_index::<E>(
                column_index as usize,
                &self.spec,
            ))
            .cloned()
            .collect::<Vec<_>>()
    }

    /// TESTING ONLY. Build a dummy NetworkGlobals instance.
    pub fn new_test_globals(
        trusted_peers: Vec<PeerId>,
        log: &slog::Logger,
        config: Arc<NetworkConfig>,
        spec: Arc<ChainSpec>,
    ) -> NetworkGlobals<E> {
        let metadata = MetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: Default::default(),
            syncnets: Default::default(),
            custody_subnet_count: spec.custody_requirement,
        });
        Self::new_test_globals_with_metadata(trusted_peers, metadata, log, config, spec)
    }

    pub(crate) fn new_test_globals_with_metadata(
        trusted_peers: Vec<PeerId>,
        metadata: MetaData<E>,
        log: &slog::Logger,
        config: Arc<NetworkConfig>,
        spec: Arc<ChainSpec>,
    ) -> NetworkGlobals<E> {
        use crate::CombinedKeyExt;
        let keypair = libp2p::identity::secp256k1::Keypair::generate();
        let enr_key: discv5::enr::CombinedKey = discv5::enr::CombinedKey::from_secp256k1(&keypair);
        let enr = discv5::enr::Enr::builder().build(&enr_key).unwrap();
        NetworkGlobals::new(enr, metadata, trusted_peers, false, log, config, spec)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use types::{Epoch, EthSpec, MainnetEthSpec as E};

    #[test]
    fn test_sampling_subnets() {
        let log = logging::test_logger();
        let mut spec = E::default_spec();
        spec.eip7594_fork_epoch = Some(Epoch::new(0));

        let custody_subnet_count = spec.data_column_sidecar_subnet_count / 2;
        let subnet_sampling_size = std::cmp::max(custody_subnet_count, spec.samples_per_slot);
        let metadata = get_metadata(custody_subnet_count);
        let config = Arc::new(NetworkConfig::default());

        let globals = NetworkGlobals::<E>::new_test_globals_with_metadata(
            vec![],
            metadata,
            &log,
            config,
            Arc::new(spec),
        );
        assert_eq!(
            globals.sampling_subnets.len(),
            subnet_sampling_size as usize
        );
    }

    #[test]
    fn test_sampling_columns() {
        let log = logging::test_logger();
        let mut spec = E::default_spec();
        spec.eip7594_fork_epoch = Some(Epoch::new(0));

        let custody_subnet_count = spec.data_column_sidecar_subnet_count / 2;
        let subnet_sampling_size = std::cmp::max(custody_subnet_count, spec.samples_per_slot);
        let metadata = get_metadata(custody_subnet_count);
        let config = Arc::new(NetworkConfig::default());

        let globals = NetworkGlobals::<E>::new_test_globals_with_metadata(
            vec![],
            metadata,
            &log,
            config,
            Arc::new(spec),
        );
        assert_eq!(
            globals.sampling_columns.len(),
            subnet_sampling_size as usize
        );
    }

    fn get_metadata(custody_subnet_count: u64) -> MetaData<E> {
        MetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: Default::default(),
            syncnets: Default::default(),
            custody_subnet_count,
        })
    }
}
