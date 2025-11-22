//! Binary for generating hash-sig keys for genesis generation
//!
//! This binary is used by the generate-genesis.sh script to generate XMSS validator keys.

use clap::Parser;
use lean_keystore::HashSigKeyConfig;
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "generate_keys")]
#[command(about = "Generate hash-sig validator keys for genesis generation")]
struct Args {
    /// Number of validators to generate
    #[arg(long, short = 'n', value_name = "COUNT")]
    num_validators: u64,

    /// Log2 of active epochs for XMSS keys
    #[arg(long, value_name = "LOG2", default_value = "24")]
    log_num_active_epochs: u64,

    /// Output directory for generated keys
    #[arg(long, short = 'o', value_name = "DIR")]
    output_dir: PathBuf,
}

fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("Generating {} validator keys with active_epoch={}", 
             args.num_validators, args.log_num_active_epochs);

    let key_config = HashSigKeyConfig::new(args.num_validators, args.log_num_active_epochs)
        .with_output_dir(args.output_dir.clone());

    match key_config.generate_and_store() {
        Ok(key_pairs) => {
            println!("Successfully generated {} key pairs", key_pairs.len());
            println!("Keys saved to: {:?}", args.output_dir);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Error generating keys: {}", e);
            std::process::exit(1);
        }
    }
}
