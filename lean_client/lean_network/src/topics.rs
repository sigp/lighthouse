/// Gossipsub topic names for the lean client network
///
/// These topics are defined in the lean specification and correspond to the message types
/// that can be propagated across the network.
/// See: leanSpec/src/lean_spec/subspecs/networking/gossipsub/topic.py
use std::fmt;
use std::str::FromStr;

/// Topic prefix matching the spec's lean network implementation.
pub const TOPIC_PREFIX: &str = "leanconsensus";

/// Gossip encoding string used for SSZ + Snappy payloads.
pub const ENCODING: &str = "ssz_snappy";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    Block,
    Attestation,
}

impl Topic {
    pub fn as_str(&self) -> &'static str {
        match self {
            Topic::Block => "block",
            Topic::Attestation => "attestation",
        }
    }

    pub fn iter() -> impl Iterator<Item = Topic> {
        [Topic::Block, Topic::Attestation].into_iter()
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Topic {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "block" => Ok(Topic::Block),
            "attestation" => Ok(Topic::Attestation),
            _ => Err(format!("Unknown topic: {}", s)),
        }
    }
}

/// Builds the fully-qualified gossipsub topic string for the given base topic.
pub fn encode_topic(network_name: &str, topic: Topic) -> String {
    format!("/{}/{}/{}/{}", TOPIC_PREFIX, network_name, topic, ENCODING)
}

/// Returns a list of encoded gossipsub topics for the provided network name.
pub fn get_topics(network_name: &str) -> Vec<String> {
    Topic::iter()
        .map(|topic| encode_topic(network_name, topic))
        .collect()
}

/// Attempts to parse a fully-qualified topic string, returning the base topic if it matches the
/// expected prefix, network, and encoding.
pub fn parse_topic_name(topic: &str, expected_network: &str) -> Option<Topic> {
    let trimmed = topic.trim_start_matches('/');
    let mut iter = trimmed.split('/');
    let prefix = iter.next()?;
    let network = iter.next()?;
    let name = iter.next()?;
    let encoding = iter.next()?;

    if prefix == TOPIC_PREFIX
        && network == expected_network
        && encoding == ENCODING
        && iter.next().is_none()
    {
        Topic::from_str(name).ok()
    } else {
        None
    }
}
