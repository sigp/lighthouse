use clap::ArgMatches;
use discv5::{enr::CombinedKey, Enr};
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// A set of configuration parameters for the bootnode, established from CLI arguments.
pub struct BootNodeConfig {
    pub listen_socket: SocketAddr,
    // TODO: Generalise to multiaddr
    pub boot_nodes: Vec<Enr>,
    pub local_enr: Enr,
    pub local_key: CombinedKey,
    pub auto_update: bool,
}

impl TryFrom<&ArgMatches<'_>> for BootNodeConfig {
    type Error = String;

    fn try_from(matches: &ArgMatches<'_>) -> Result<Self, Self::Error> {
        let listen_address = matches
            .value_of("listen-address")
            .expect("required parameter")
            .parse::<IpAddr>()
            .map_err(|_| "Invalid listening address".to_string())?;

        let listen_port = matches
            .value_of("port")
            .expect("required parameter")
            .parse::<u16>()
            .map_err(|_| "Invalid listening port".to_string())?;

        let boot_nodes = {
            if let Some(boot_nodes) = matches.value_of("boot-nodes") {
                boot_nodes
                    .split(',')
                    .map(|enr| enr.parse().map_err(|_| format!("Invalid ENR: {}", enr)))
                    .collect::<Result<Vec<Enr>, _>>()?
            } else {
                Vec::new()
            }
        };

        let enr_port = {
            if let Some(port) = matches.value_of("boot-node-enr-port") {
                port.parse::<u16>()
                    .map_err(|_| "Invalid ENR port".to_string())?
            } else {
                listen_port
            }
        };

        let enr_address = {
            let address_string = matches
                .value_of("boot-node-enr-address")
                .expect("required parameter");
            resolve_address(address_string.into(), enr_port)?
        };

        let auto_update = matches.is_present("enable-enr_auto_update");

        // the address to listen on
        let listen_socket = SocketAddr::new(listen_address, enr_port);

        // Generate a new key and build a new ENR
        let local_key = CombinedKey::generate_secp256k1();
        let local_enr = discv5::enr::EnrBuilder::new("v4")
            .ip(enr_address)
            .udp(enr_port)
            .build(&local_key)
            .map_err(|e| format!("Failed to build ENR: {:?}", e))?;

        Ok(BootNodeConfig {
            listen_socket,
            boot_nodes,
            local_enr,
            local_key,
            auto_update,
        })
    }
}

/// Resolves an IP/DNS string to an IpAddr.
fn resolve_address(address_string: String, port: u16) -> Result<IpAddr, String> {
    match address_string.parse::<IpAddr>() {
        Ok(addr) => Ok(addr), // valid IpAddr
        Err(_) => {
            let mut addr = address_string.clone();
            // Appending enr-port to the dns hostname to appease `to_socket_addrs()` parsing.
            addr.push_str(&format!(":{}", port.to_string()));
            // `to_socket_addr()` does the dns resolution
            // Note: `to_socket_addrs()` is a blocking call
            addr.to_socket_addrs()
                .map(|mut resolved_addrs|
                    // Pick the first ip from the list of resolved addresses
                    resolved_addrs
                        .next()
                        .map(|a| a.ip())
                        .ok_or_else(|| "Resolved dns addr contains no entries".to_string()))
                .map_err(|_| format!("Failed to parse enr-address: {}", address_string))?
        }
    }
}
