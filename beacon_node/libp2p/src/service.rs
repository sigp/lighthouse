use slog::debug;

/// The configuration and state of the libp2p components for the beacon node.
pub struct Service {}

impl Service {
    pub fn new(log: slog::Logger) -> Self {
        debug!(log, "Service starting");
        Service {}
    }
}
