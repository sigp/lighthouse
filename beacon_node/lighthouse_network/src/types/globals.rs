//! A collection of variables that are accessible outside of the network thread itself.
use crate::peer_manager::peerdb::PeerDB;
use crate::rpc::{MetaData, MetaDataV3};
use crate::types::{BackFillState, SyncState};
use crate::Client;
use crate::EnrExt;
use crate::{Enr, GossipTopic, Multiaddr, PeerId};
use itertools::Itertools;
use parking_lot::RwLock;
use std::collections::HashSet;
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
    /// The computed custody subnets and columns is stored to avoid re-computing.
    pub custody_subnets: Vec<DataColumnSubnetId>,
    pub custody_columns: Vec<ColumnIndex>,
    pub spec: ChainSpec,
}

impl<E: EthSpec> NetworkGlobals<E> {
    pub fn new(
        enr: Enr,
        local_metadata: MetaData<E>,
        trusted_peers: Vec<PeerId>,
        disable_peer_scoring: bool,
        log: &slog::Logger,
        spec: ChainSpec,
    ) -> Self {
        let (custody_subnets, custody_columns) = if spec.is_peer_das_scheduled() {
            let custody_subnet_count = local_metadata
                .custody_subnet_count()
                .copied()
                .expect("custody subnet count must be set if PeerDAS is scheduled");
            let custody_subnets = DataColumnSubnetId::compute_custody_subnets::<E>(
                enr.node_id().raw(),
                custody_subnet_count,
                &spec,
            )
            .expect("custody subnet count must be valid")
            .collect::<Vec<_>>();
            let custody_columns = custody_subnets
                .iter()
                .flat_map(|subnet| subnet.columns::<E>(&spec))
                .sorted()
                .collect();
            (custody_subnets, custody_columns)
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
            backfill_state: RwLock::new(BackFillState::NotRequired),
            custody_subnets,
            custody_columns,
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
        spec: ChainSpec,
    ) -> NetworkGlobals<E> {
        let metadata = MetaData::V3(MetaDataV3 {
            seq_number: 0,
            attnets: Default::default(),
            syncnets: Default::default(),
            custody_subnet_count: spec.custody_requirement,
        });
        Self::new_test_globals_with_metadata(trusted_peers, metadata, log, spec)
    }

    pub(crate) fn new_test_globals_with_metadata(
        trusted_peers: Vec<PeerId>,
        metadata: MetaData<E>,
        log: &slog::Logger,
        spec: ChainSpec,
    ) -> NetworkGlobals<E> {
        use crate::CombinedKeyExt;
        let keypair = libp2p::identity::secp256k1::Keypair::generate();
        let enr_key: discv5::enr::CombinedKey = discv5::enr::CombinedKey::from_secp256k1(&keypair);
        let enr = discv5::enr::Enr::builder().build(&enr_key).unwrap();
        NetworkGlobals::new(enr, metadata, trusted_peers, false, log, spec)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use types::{Epoch, EthSpec, MainnetEthSpec as E};

    #[test]
    fn test_custody_subnets() {
        let log = logging::test_logger();
        let mut spec = E::default_spec();
        spec.eip7594_fork_epoch = Some(Epoch::new(0));

        let custody_subnet_count = spec.data_column_sidecar_subnet_count / 2;
        let metadata = get_metadata(custody_subnet_count);

        let globals =
            NetworkGlobals::<E>::new_test_globals_with_metadata(vec![], metadata, &log, spec);
        assert_eq!(globals.custody_subnets.len(), custody_subnet_count as usize);
    }

    #[test]
    fn test_custody_columns() {
        let log = logging::test_logger();
        let mut spec = E::default_spec();
        spec.eip7594_fork_epoch = Some(Epoch::new(0));

        let custody_subnet_count = spec.data_column_sidecar_subnet_count / 2;
        let custody_columns_count = spec.number_of_columns / 2;
        let metadata = get_metadata(custody_subnet_count);

        let globals =
            NetworkGlobals::<E>::new_test_globals_with_metadata(vec![], metadata, &log, spec);
        assert_eq!(globals.custody_columns.len(), custody_columns_count);
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
