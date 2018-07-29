extern crate secp256k1;
extern crate libp2p_peerstore;
extern crate rand;
extern crate hex;

use std;
use std::io::prelude::*;
use std::fs::File;
use slog::Logger;

use std::io::Error as IoError;
use std::path::Path;
use super::config::NetworkConfig;
use self::secp256k1::key::{ SecretKey, PublicKey };
use self::libp2p_peerstore::PeerId;

const LOCAL_PK_FILE: &str = "local.pk";
const LOCAL_SK_FILE: &str = "local.sk";
const BOOTSTRAP_PK_FILE: &str = "bootstrap.pk";

fn get_curve() -> secp256k1::Secp256k1 { secp256k1::Secp256k1::new() }

/// Generates a new public and secret key pair and writes them to 
/// individual files.
pub fn generate_keys(config: NetworkConfig, log: &Logger)
    -> Result<(), IoError>
{
    info!(log, "Generating keys...");
    let mut rng = rand::thread_rng();
    let curve = get_curve();
    let s = SecretKey::new(&curve, &mut rng);
    let p = PublicKey::from_secret_key(&curve, &s).unwrap();
    let p_vec = p.serialize_vec(&curve, false);
    let s_vec = &s[..];
    let p_string = hex::encode(p_vec);
    let s_string = hex::encode(s_vec);
    let mut p_file = File::create(LOCAL_PK_FILE)?;
    let mut s_file = File::create(LOCAL_SK_FILE)?;
    info!(log, "Writing public key...");
    p_file.write(p_string.as_bytes())?;
    info!(log, "Writing secret key...");
    s_file.write(s_string.as_bytes())?;
    Ok(())
}
