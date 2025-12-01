use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use libp2p_identity::{PublicKey, ed25519, secp256k1};
use std::net::IpAddr;
use std::path::Path;
use tracing::{debug, error, warn};

/// Loads bootstrap nodes from nodes.yaml using ENR records
///
/// # Arguments
/// * `nodes_path` - Path to the nodes.yaml file containing ENR records
///
/// # Returns
/// A vector of multiaddr strings for each bootstrap node. Invalid entries are skipped with warnings.
pub fn load_bootstrap_nodes<P: AsRef<Path>>(nodes_path: P) -> Result<Vec<String>, String> {
    let path = nodes_path.as_ref();

    // Check if file exists
    if !path.exists() {
        return Err(format!("nodes.yaml file does not exist at {:?}", path));
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read nodes.yaml file: {}", e))?;

    if content.trim().is_empty() {
        return Err(format!("nodes.yaml file at {:?} is empty", path));
    }

    debug!(
        "Reading nodes.yaml from {:?}, content length: {} bytes",
        path,
        content.len()
    );

    // Parse as YAML array of ENR strings
    let enr_records: Vec<String> = serde_yaml::from_str(&content).map_err(|e| {
        format!(
            "Failed to parse nodes.yaml as YAML: {}. Content preview: {}",
            e,
            content.chars().take(200).collect::<String>()
        )
    })?;

    debug!("Parsed {} ENR records from nodes.yaml", enr_records.len());

    let mut multiaddrs = Vec::new();
    let mut parse_errors = Vec::new();

    for (i, enr_str) in enr_records.iter().enumerate() {
        if enr_str.is_empty() {
            warn!("ENR record #{} is empty, skipping", i);
            continue;
        }

        match parse_enr_to_multiaddr(enr_str) {
            Ok(multiaddr) => {
                let multiaddr_str = multiaddr.to_string();
                debug!("Loaded bootstrap node #{} from ENR: {}", i, multiaddr_str);
                multiaddrs.push(multiaddr_str);
            }
            Err(e) => {
                let error_msg = format!("Failed to parse ENR record #{}: {}", i, e);
                warn!("{}", error_msg);
                parse_errors.push((i, error_msg));
            }
        }
    }

    if multiaddrs.is_empty() {
        let error_details = if !parse_errors.is_empty() {
            format!(
                "All {} ENR records failed to parse. First error: {}",
                enr_records.len(),
                parse_errors[0].1
            )
        } else {
            format!("No ENR records found in file")
        };
        error!(
            "No valid bootstrap nodes found in {:?}. {}",
            path, error_details
        );
        return Err(format!(
            "No valid bootstrap nodes found in {:?}. {}",
            path, error_details
        ));
    } else {
        debug!(
            "Loaded {} bootstrap nodes from {:?} ({} failed to parse)",
            multiaddrs.len(),
            path,
            parse_errors.len()
        );
    }

    Ok(multiaddrs)
}

/// Parses an ENR record string to extract multiaddr
/// ENR records are base64-encoded and contain IP/port information
///
/// This follows the same pattern used elsewhere in Lighthouse:
/// - Uses standard ENR fields: ip4/ip6 for IP addresses
/// - Uses get_decodable("quic") for QUIC port
/// - Falls back to udp4/udp6 if quic port is not available
pub fn parse_enr_to_multiaddr(enr_str: &str) -> Result<Multiaddr, String> {
    // ENR format: enr:-IW4Q...
    let enr = enr_str
        .parse::<enr::Enr<enr::CombinedKey>>()
        .map_err(|e| format!("Failed to parse ENR string: {:?}", e))?;

    debug!("Parsed ENR: seq={}, id={:?}", enr.seq(), enr.id());

    // Extract IP address - use standard ENR fields
    let ip = enr
        .ip4()
        .map(|ip| IpAddr::V4(ip))
        .or_else(|| enr.ip6().map(|ip| IpAddr::V6(ip)))
        .ok_or_else(|| {
            let has_ip4 = enr.ip4().is_some();
            let has_ip6 = enr.ip6().is_some();
            format!("ENR has no IP address (ip4: {}, ip6: {})", has_ip4, has_ip6)
        })?;

    // Extract QUIC port using get_decodable
    // The "quic" key is decoded as u16 automatically by get_decodable
    let port = enr
        .get_decodable::<u16>("quic")
        .and_then(Result::ok)
        .or_else(|| enr.udp4())
        .or_else(|| enr.udp6())
        .ok_or_else(|| {
            let has_udp4 = enr.udp4().is_some();
            let has_udp6 = enr.udp6().is_some();
            let has_quic = enr.get_decodable::<u16>("quic").is_some();
            format!(
                "ENR has no UDP/QUIC port (udp4: {}, udp6: {}, quic: {})",
                has_udp4, has_udp6, has_quic
            )
        })?;

    // Extract peer ID from ENR public key
    let peer_id = extract_peer_id_from_enr(&enr)?;

    // Build multiaddr with peer ID (matching format: /ip4/127.0.0.1/udp/9000/quic-v1/p2p/{peer_id})
    let mut multiaddr = match ip {
        IpAddr::V4(ipv4) => format!("/ip4/{}/udp/{}/quic-v1", ipv4, port)
            .parse::<Multiaddr>()
            .map_err(|e| format!("Failed to construct multiaddr: {}", e))?,
        IpAddr::V6(ipv6) => format!("/ip6/{}/udp/{}/quic-v1", ipv6, port)
            .parse::<Multiaddr>()
            .map_err(|e| format!("Failed to construct multiaddr: {}", e))?,
    };

    // Add peer ID to multiaddr (as shown in validator-config.yaml comments)
    // Format: /ip4/127.0.0.1/udp/9000/quic-v1/p2p/{peer_id}
    multiaddr.push(Protocol::P2p(peer_id));

    Ok(multiaddr)
}

/// Extracts the libp2p PeerId from an ENR's public key
/// This matches the implementation in network_utils::enr_ext::EnrExt::peer_id
fn extract_peer_id_from_enr(enr: &enr::Enr<enr::CombinedKey>) -> Result<PeerId, String> {
    let public_key = enr.public_key();
    let peer_id = match public_key {
        enr::CombinedPublicKey::Secp256k1(pk) => {
            let pk_bytes = pk.to_sec1_bytes();
            let libp2p_pk: PublicKey = secp256k1::PublicKey::try_from_bytes(&pk_bytes)
                .map_err(|e| format!("Failed to parse secp256k1 public key: {:?}", e))?
                .into();
            PeerId::from_public_key(&libp2p_pk)
        }
        enr::CombinedPublicKey::Ed25519(pk) => {
            let pk_bytes = pk.to_bytes();
            let libp2p_pk: PublicKey = ed25519::PublicKey::try_from_bytes(&pk_bytes)
                .map_err(|e| format!("Failed to parse ed25519 public key: {:?}", e))?
                .into();
            PeerId::from_public_key(&libp2p_pk)
        }
    };
    Ok(peer_id)
}
