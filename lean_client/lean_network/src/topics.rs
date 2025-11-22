/// Gossipsub topic names for the lean client network
///
/// These topics are defined in the lean specification and correspond to the message types
/// that can be propagated across the network.
/// See: leanSpec/src/lean_spec/subspecs/networking/gossipsub/topic.py

/// Topic for gossiping new blocks
pub const BLOCK_TOPIC: &str = "block";

/// Topic for gossiping new attestations
pub const ATTESTATION_TOPIC: &str = "attestation";

/// Returns a list of all gossipsub topics to subscribe to
pub fn get_topics() -> Vec<&'static str> {
    vec![BLOCK_TOPIC, ATTESTATION_TOPIC]
}
