//! A collection of variables that are accessible outside of the network thread itself.
use crate::discovery::peer_id_to_node_id;
use crate::peer_manager::peerdb::PeerDB;
use crate::rpc::{MetaData, MetaDataV2};
use crate::types::{BackFillState, SyncState};
use crate::EnrExt;
use crate::{Client, Eth2Enr};
use crate::{Enr, GossipTopic, Multiaddr, PeerId};
use discv5::handler::NodeContact;
use itertools::Itertools;
use parking_lot::RwLock;
use slog::{debug, Logger};
use std::collections::HashSet;
use types::data_column_sidecar::ColumnIndex;
use types::{ChainSpec, DataColumnSubnetId, Epoch, EthSpec};

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
}

impl<E: EthSpec> NetworkGlobals<E> {
    pub fn new(
        enr: Enr,
        local_metadata: MetaData<E>,
        trusted_peers: Vec<PeerId>,
        disable_peer_scoring: bool,
        log: &slog::Logger,
    ) -> Self {
        NetworkGlobals {
            local_enr: RwLock::new(enr.clone()),
            peer_id: RwLock::new(enr.peer_id()),
            listen_multiaddrs: RwLock::new(Vec::new()),
            local_metadata: RwLock::new(local_metadata),
            peers: RwLock::new(PeerDB::new(trusted_peers, disable_peer_scoring, log)),
            gossipsub_subscriptions: RwLock::new(HashSet::new()),
            sync_state: RwLock::new(SyncState::Stalled),
            backfill_state: RwLock::new(BackFillState::NotRequired),
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

    /// Compute custody data columns the node is assigned to custody.
    pub fn custody_columns(&self, _epoch: Epoch, spec: &ChainSpec) -> Vec<ColumnIndex> {
        let enr = self.local_enr();
        let node_id = enr.node_id().raw().into();
        let custody_subnet_count = enr.custody_subnet_count::<E>(spec);
        DataColumnSubnetId::compute_custody_columns::<E>(node_id, custody_subnet_count, spec)
            .collect()
    }

    /// Compute custody data column subnets the node is assigned to custody.
    pub fn custody_subnets(&self, spec: &ChainSpec) -> impl Iterator<Item = DataColumnSubnetId> {
        let enr = self.local_enr();
        let node_id = enr.node_id().raw().into();
        let custody_subnet_count = enr.custody_subnet_count::<E>(spec);
        DataColumnSubnetId::compute_custody_subnets::<E>(node_id, custody_subnet_count, spec)
    }

    pub fn custody_peers_for_column(
        &self,
        column_index: ColumnIndex,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Vec<PeerId> {
        self.peers
            .read()
            .connected_peers()
            .filter_map(|(peer_id, peer_info)| {
                let node_id_and_csc = if let Some(enr) = peer_info.enr() {
                    let custody_subnet_count = enr.custody_subnet_count::<E>(spec);
                    Some((enr.node_id(), custody_subnet_count))
                } else if let Some(node_id) = peer_id_to_node_id(peer_id)
                    // TODO(das): may be noisy, downgrade to trace
                    .inspect_err(
                        |e| debug!(log, "Error converting peer ID to node ID"; "error" => ?e),
                    )
                    .ok()
                {
                    // TODO(das): may be noisy, downgrade to trace
                    debug!(
                        log,
                        "ENR not present for peer";
                        "peer_id" => %peer_id,
                        "info" => "Unable to compute custody columns, falling back to default \
                        custody requirement",
                    );
                    // TODO(das): Use `custody_subnet_count` from `MetaDataV3`
                    Some((node_id, spec.custody_requirement))
                } else {
                    None
                };

                node_id_and_csc.and_then(|(node_id, custody_subnet_count)| {
                    // TODO(das): consider caching a map of subnet -> Vec<PeerId> and invalidating
                    // whenever a peer connected or disconnect event in received
                    DataColumnSubnetId::compute_custody_columns::<E>(
                        node_id.raw().into(),
                        custody_subnet_count,
                        spec,
                    )
                    .contains(&column_index)
                    .then_some(*peer_id)
                })
            })
            .collect::<Vec<_>>()
    }

    /// TESTING ONLY. Build a dummy NetworkGlobals instance.
    pub fn new_test_globals(trusted_peers: Vec<PeerId>, log: &slog::Logger) -> NetworkGlobals<E> {
        use crate::CombinedKeyExt;
        let keypair = libp2p::identity::secp256k1::Keypair::generate();
        let enr_key: discv5::enr::CombinedKey = discv5::enr::CombinedKey::from_secp256k1(&keypair);
        let enr = discv5::enr::Enr::builder().build(&enr_key).unwrap();
        NetworkGlobals::new(
            enr,
            MetaData::V2(MetaDataV2 {
                seq_number: 0,
                attnets: Default::default(),
                syncnets: Default::default(),
            }),
            trusted_peers,
            false,
            log,
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use types::{Epoch, EthSpec, MainnetEthSpec as E};

    #[test]
    fn test_custody_count_default() {
        let spec = E::default_spec();
        let log = logging::test_logger();
        let default_custody_requirement_column_count = spec.number_of_columns as u64
            / spec.data_column_sidecar_subnet_count
            * spec.custody_requirement;
        let globals = NetworkGlobals::<E>::new_test_globals(vec![], &log);
        let any_epoch = Epoch::new(0);
        let columns = globals.custody_columns(any_epoch, &spec);
        assert_eq!(
            columns.len(),
            default_custody_requirement_column_count as usize
        );
    }

    #[test]
    fn custody_peers_for_column_enr_present() {
        let spec = E::default_spec();
        let log = logging::test_logger();
        let globals = NetworkGlobals::<E>::new_test_globals(vec![], &log);

        let mut peers_db_write_lock = globals.peers.write();
        let valid_enrs = [
            "enr:-Mm4QDJpcg5mZ8EFeYuDcUX78tOTigHLz4_zJlCY7vOTd2-XPPqlAoWM02Us69c4ov85pHgTgeo77Z3_nAhJ4yF1y30Bh2F0dG5ldHOIAAAAAAAAAACDY3NjIIRldGgykAHMVa1gAAA4AOH1BQAAAACCaWSCdjSCaXCEiPMgroRxdWljgpR0iXNlY3AyNTZrMaECvF7Y-fD1MEEVQq3y5qW7C8UoTsq6J_tfwvQIJ5fo1TGIc3luY25ldHMAg3RjcIKUc4N1ZHCClHM",
            "enr:-Mm4QBw4saycbk-Up2PvppJOv0KzBqgFFHl6_OfFlh8_HxtwWkZpSFgJ0hFV3qOelh_Ai4L9HhSAEJSG48LE8YJ-7WABh2F0dG5ldHOIAAAAAAAAAACDY3NjIIRldGgykAHMVa1gAAA4AOH1BQAAAACCaWSCdjSCaXCEiPMgroRxdWljgpR1iXNlY3AyNTZrMaECsRjhgRrAuRWelB9VTTzTa0tHtcWyLTLSReL4RNWhJgGIc3luY25ldHMAg3RjcIKUdIN1ZHCClHQ",
            "enr:-Mm4QMFlqbpGrmN21EM-70_hDW9c3MrulhIZElmsP3kb7XSLOEmV7-Msj2jlwGR5C_TicwOXYsZrN6eEIJlGgluM_XgBh2F0dG5ldHOIAAAAAAAAAACDY3NjAYRldGgykAHMVa1gAAA4AOH1BQAAAACCaWSCdjSCaXCEiPMgroRxdWljgpR2iXNlY3AyNTZrMaECpAOonvUcYbBX8Tf0ErNPKwJeeidKzJftLTryBZUusMSIc3luY25ldHMAg3RjcIKUdYN1ZHCClHU",
            "enr:-Mm4QEHdVjmQ7mH2qIX7_6SDablQUcrZuA4Sxjprh9WGbipfHUjPrELtBaRIRJUrpI8cgJRoAF1wMwoeRS7j3d8xviRGh2F0dG5ldHOIAAAAAAAAAACDY3NjAYRldGgykAHMVa1gAAA4AOH1BQAAAACCaWSCdjSCaXCEiPMgroRxdWljgpR2iXNlY3AyNTZrMaECpAOonvUcYbBX8Tf0ErNPKwJeeidKzJftLTryBZUusMSIc3luY25ldHMAg3RjcIKUdYN1ZHCClHU"
        ];
        let peers = valid_enrs
            .into_iter()
            .map(|enr_str| {
                let enr = Enr::from_str(enr_str).unwrap();
                let peer_id = enr.peer_id();
                peers_db_write_lock.__add_connected_peer_enr_testing_only(enr);
                peer_id
            })
            .collect::<Vec<_>>();

        drop(peers_db_write_lock);
        let [supernode_peer_1, supernode_peer_2, _, _] =
            peers.try_into().expect("expected exactly 4 peer ids");

        for col_index in 0..spec.number_of_columns {
            let custody_peers =
                globals.custody_peers_for_column(col_index as ColumnIndex, &spec, &log);
            assert!(
                custody_peers.contains(&supernode_peer_1),
                "must at least return supernode peer"
            );
            assert!(
                custody_peers.contains(&supernode_peer_2),
                "must at least return supernode peer"
            );
        }
    }

    // If ENR is not preset, fallback to deriving node_id and use `spec.custody_requirement`.
    #[test]
    fn custody_peers_for_column_no_enr_use_default() {
        let spec = E::default_spec();
        let log = logging::test_logger();
        let globals = NetworkGlobals::<E>::new_test_globals(vec![], &log);

        // Add peer without enr
        let peer_id_str = "16Uiu2HAm86zWajwnBFD8uxkRpxhRzeUEf6Brfz2VBxGAaWx9ejyr";
        let peer_id = PeerId::from_str(peer_id_str).unwrap();
        let multiaddr =
            Multiaddr::from_str(&format!("/ip4/0.0.0.0/udp/9000/p2p/{peer_id_str}")).unwrap();

        let mut peers_db_write_lock = globals.peers.write();
        peers_db_write_lock.__add_connected_peer_multiaddr_testing_only(&peer_id, multiaddr);
        drop(peers_db_write_lock);

        let custody_subnets = (0..spec.data_column_sidecar_subnet_count)
            .filter(|col_index| {
                !globals
                    .custody_peers_for_column(*col_index, &spec, &log)
                    .is_empty()
            })
            .count();

        // The single peer's custody subnet should match custody_requirement.
        assert_eq!(custody_subnets, spec.custody_requirement as usize);
    }
}
