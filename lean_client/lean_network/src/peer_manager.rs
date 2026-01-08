use crate::status::StatusMessage;
use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use types::Hash256;

/// Events observed by the network service and forwarded to the peer manager.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    Connected(PeerId),
    Disconnected(PeerId),
    StatusReceived(PeerId, StatusMessage),
}

/// Commands issued by the peer manager for the network service to execute.
#[derive(Debug, Clone)]
pub enum PeerCommand {
    Dial(Multiaddr),
}

#[derive(Debug, Clone)]
struct PeerRecord {
    connected: bool,
    attempts: u32,
    next_dial_at: Instant,
    latest_status: Option<StatusMessage>,
}

impl PeerRecord {
    fn new(now: Instant) -> Self {
        Self {
            connected: false,
            attempts: 0,
            next_dial_at: now,
            latest_status: None,
        }
    }
}

/// Async peer manager.
///
/// Responsibilities:
/// - Track bootstrap peers and reconnect with exponential backoff.
/// - Track the latest received head (via status messages) per peer.
/// - Provide dial commands to the network service.
pub struct PeerManager {
    /// Bootstrap peers we actively try to keep connected to.
    bootstrap: HashMap<PeerId, Multiaddr>,
    /// Per-peer state (includes latest status).
    peers: HashMap<PeerId, PeerRecord>,
    base_backoff: Duration,
    max_backoff: Duration,
    /// Receive events from network service.
    event_rx: mpsc::Receiver<PeerEvent>,
    /// Send dial commands to network service.
    cmd_tx: mpsc::Sender<PeerCommand>,
}

impl PeerManager {
    pub fn new(
        bootstrap: Vec<(PeerId, Multiaddr)>,
        base_backoff: Duration,
        max_backoff: Duration,
        event_rx: mpsc::Receiver<PeerEvent>,
        cmd_tx: mpsc::Sender<PeerCommand>,
    ) -> Self {
        let now = Instant::now();
        let mut bootstrap_map = HashMap::new();
        let mut peers = HashMap::new();

        for (peer_id, addr) in bootstrap {
            bootstrap_map.insert(peer_id, addr);
            peers.entry(peer_id).or_insert_with(|| PeerRecord::new(now));
        }

        Self {
            bootstrap: bootstrap_map,
            peers,
            base_backoff,
            max_backoff,
            event_rx,
            cmd_tx,
        }
    }

    pub async fn run(mut self) {
        loop {
            let now = Instant::now();
            let next_wake = self.next_wake(now);
            tokio::select! {
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next_wake)) => {
                    self.dial_due(now).await;
                }
                maybe_ev = self.event_rx.recv() => {
                    match maybe_ev {
                        Some(ev) => self.on_event(ev),
                        None => return, // network service dropped sender
                    }
                }
            }
        }
    }

    fn next_wake(&self, now: Instant) -> Instant {
        let mut next = now + self.base_backoff;
        for (peer_id, _addr) in &self.bootstrap {
            if let Some(rec) = self.peers.get(peer_id) {
                if !rec.connected && rec.next_dial_at < next {
                    next = rec.next_dial_at;
                }
            }
        }
        next
    }

    fn on_event(&mut self, ev: PeerEvent) {
        let now = Instant::now();
        match ev {
            PeerEvent::Connected(peer_id) => {
                let rec = self.peers.entry(peer_id).or_insert_with(|| PeerRecord::new(now));
                rec.connected = true;
                rec.attempts = 0;
                rec.next_dial_at = now + self.base_backoff;
            }
            PeerEvent::Disconnected(peer_id) => {
                let rec = self.peers.entry(peer_id).or_insert_with(|| PeerRecord::new(now));
                rec.connected = false;
                rec.next_dial_at = now; // dial ASAP on next tick
            }
            PeerEvent::StatusReceived(peer_id, status) => {
                let rec = self.peers.entry(peer_id).or_insert_with(|| PeerRecord::new(now));
                rec.latest_status = Some(status);
            }
        }
    }

    async fn dial_due(&mut self, now: Instant) {
        for (peer_id, addr) in self.bootstrap.clone() {
            let Some(rec) = self.peers.get_mut(&peer_id) else { continue };
            if rec.connected || now < rec.next_dial_at {
                continue;
            }

            // Issue dial.
            if let Err(e) = self.cmd_tx.send(PeerCommand::Dial(addr.clone())).await {
                warn!("PeerManager failed to send dial command: {}", e);
                return;
            }

            // Exponential backoff scheduling.
            rec.attempts = rec.attempts.saturating_add(1);
            let shift = rec.attempts.min(30); // cap to avoid overflow in u32 multiplier
            let mult = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
            let mut delay = self.base_backoff.saturating_mul(mult);
            if delay > self.max_backoff {
                delay = self.max_backoff;
            }
            rec.next_dial_at = now + delay;

            debug!(
                peer = ?peer_id,
                attempts = rec.attempts,
                next_in_secs = delay.as_secs(),
                "Scheduled next dial attempt"
            );
        }
    }

    /// Returns the latest head root/slot we've heard from this peer (via Status).
    #[allow(dead_code)]
    pub fn latest_head(&self, peer_id: &PeerId) -> Option<(u64, Hash256)> {
        self.peers
            .get(peer_id)
            .and_then(|r| r.latest_status.as_ref())
            .map(|s| (s.head_slot, s.head_root))
    }
}


