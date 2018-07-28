extern crate secp256k1;
extern crate libp2p_peerstore;
extern crate rand;
extern crate hex;

use std;
use std::io::prelude::*;
use std::fs::File;
use slog::Logger;

use self::secp256k1::key::{ SecretKey, PublicKey };
use self::libp2p_peerstore::PeerId;

const LOCAL_PK_FILE: &str = "local.pk";
const LOCAL_SK_FILE: &str = "local.sk";
const BOOTSTRAP_PK_FILE: &str = "bootstrap.pk";

pub fn peer_id_from_pub_key(pk: &PublicKey) -> PeerId {
    let curve = get_curve();
    PeerId::from_public_key(&pk.serialize_vec(&curve, false))
}

fn get_curve() -> secp256k1::Secp256k1 { secp256k1::Secp256k1::new() }

/// Generates a new public and secret key pair and writes them to 
/// individual files.
pub fn generate_keys(log: &Logger) -> std::io::Result<()> {
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

pub fn load_bootstrap_pk(log: &Logger) -> PublicKey {
    info!(log, "Loading boostrap public key from filesystem...");
    load_pk_from_file(BOOTSTRAP_PK_FILE)
}

pub fn load_local_keys(log: &Logger) -> (PublicKey, SecretKey) {
    info!(log, "Loading local keys from filesystem...");
    (load_pk_from_file(LOCAL_PK_FILE), load_sk_from_file(LOCAL_SK_FILE))
}

fn load_sk_from_file(file: &str) -> SecretKey {
    let vec = load_vec_from_hex_file(file);
    let curve = get_curve();
    SecretKey::from_slice(&curve, &vec).expect("secret key invalid")
}

fn load_pk_from_file(file: &str) -> PublicKey {
    let vec = load_vec_from_hex_file(file);
    let curve = get_curve();
    PublicKey::from_slice(&curve, &vec).expect("public key invalid")
}

fn load_vec_from_hex_file(file: &str) -> Vec<u8> {
    let mut contents = String::new();
    let mut file = File::open(file).expect("key not found");
    file.read_to_string(&mut contents).expect("error reading from file");
    hex::decode(contents).expect("public key corrupt")
}
