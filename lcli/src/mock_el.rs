use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use execution_layer::{
    auth::JwtKey,
    test_utils::{
        Config, MockExecutionConfig, MockServer, DEFAULT_JWT_SECRET, DEFAULT_TERMINAL_BLOCK,
    },
};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use types::*;

pub fn run<E: EthSpec>(mut env: Environment<E>, matches: &ArgMatches) -> Result<(), String> {
    let jwt_path: PathBuf = parse_required(matches, "jwt-output-path")?;
    let listen_addr: Ipv4Addr = parse_required(matches, "listen-address")?;
    let listen_port: u16 = parse_required(matches, "listen-port")?;
    let all_payloads_valid: bool = parse_required(matches, "all-payloads-valid")?;
    let shanghai_time = parse_required(matches, "shanghai-time")?;
    let cancun_time = parse_optional(matches, "cancun-time")?;
    let prague_time = parse_optional(matches, "prague-time")?;

    let handle = env.core_context().executor.handle().unwrap();
    let spec = &E::default_spec();
    let jwt_key = JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap();
    std::fs::write(jwt_path, hex::encode(DEFAULT_JWT_SECRET)).unwrap();

    let config = MockExecutionConfig {
        server_config: Config {
            listen_addr,
            listen_port,
        },
        jwt_key,
        terminal_difficulty: spec.terminal_total_difficulty,
        terminal_block: DEFAULT_TERMINAL_BLOCK,
        terminal_block_hash: spec.terminal_block_hash,
        shanghai_time: Some(shanghai_time),
        cancun_time,
        prague_time,
    };
    let kzg = None;
    let server: MockServer<E> = MockServer::new_with_config(&handle, config, kzg);

    if all_payloads_valid {
        eprintln!(
            "Using --all-payloads-valid=true can be dangerous. \
            Never use this flag when operating validators."
        );
        // Indicate that all payloads are valid.
        server.all_payloads_valid();
    }

    eprintln!(
        "This tool is for TESTING PURPOSES ONLY. Do not use in production or on mainnet. \
        It cannot perform validator duties. It may cause nodes to follow an invalid chain."
    );
    eprintln!("Server listening on {}:{}", listen_addr, listen_port);

    let shutdown_reason = env.block_until_shutdown_requested()?;

    eprintln!("Shutting down: {:?}", shutdown_reason);

    Ok(())
}
