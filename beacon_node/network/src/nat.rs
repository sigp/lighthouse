//! This houses various NAT hole punching strategies.
//!
//! Currently supported strategies:
//! - UPnP

use anyhow::{bail, Context, Error};
use igd_next::{aio::tokio as igd, PortMappingProtocol};
use slog::debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::sleep;

/// The duration in seconds of a port mapping on the gateway.
const MAPPING_DURATION: u32 = 3600;

/// Renew the Mapping every half of `MAPPING_DURATION` to avoid the port being unmapped.
const MAPPING_TIMEOUT: u64 = MAPPING_DURATION as u64 / 2;

/// Attempts to map Discovery external port mappings with UPnP.
pub async fn construct_upnp_mappings(
    addr: Ipv4Addr,
    port: u16,
    log: slog::Logger,
) -> Result<(), Error> {
    let gateway = igd::search_gateway(Default::default())
        .await
        .context("Gateway does not support UPnP")?;

    let external_address = gateway
        .get_external_ip()
        .await
        .context("Could not access gateway's external ip")?;

    let is_private = match external_address {
        IpAddr::V4(ipv4) => ipv4.is_private(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    };

    if is_private {
        bail!(
            "Gateway's external address is a private address: {}",
            external_address
        );
    }

    loop {
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                port,
                SocketAddr::new(IpAddr::V4(addr), port),
                MAPPING_DURATION,
                "Lighthouse Discovery port",
            )
            .await
            .with_context(|| format!("Could not UPnP map port: {} on the gateway", port))?;
        debug!(log, "Discovery UPnP port mapped"; "port" => %port);
        sleep(Duration::from_secs(MAPPING_TIMEOUT)).await;
    }
}
