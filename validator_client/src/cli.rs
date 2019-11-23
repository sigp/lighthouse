use crate::config::DEFAULT_HTTP_SERVER;
use clap::{App, Arg, SubCommand};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("validator_client")
        .visible_aliases(&["v", "vc", "validator"])
        .about("Ethereum 2.0 Validator Client")
        .arg(
            Arg::with_name("server")
                .long("server")
                .value_name("NETWORK_ADDRESS")
                .help("Address to connect to BeaconNode.")
                .default_value(&DEFAULT_HTTP_SERVER)
                .takes_value(true),
        )
        /*
         * The "testnet" sub-command.
         *
         * Used for starting testnet validator clients.
         */
        .subcommand(SubCommand::with_name("testnet")
            .about("Starts a testnet validator using INSECURE, predicatable private keys, based off the canonical \
                   validator index. ONLY USE FOR TESTING PURPOSES!")
            .subcommand(SubCommand::with_name("insecure")
                .about("Uses the standard, predicatable `interop` keygen method to produce a range \
                        of predicatable private keys and starts performing their validator duties.")
                .arg(Arg::with_name("first_validator")
                    .value_name("VALIDATOR_INDEX")
                    .required(true)
                    .help("The first validator public key to be generated for this client."))
                .arg(Arg::with_name("last_validator")
                    .value_name("VALIDATOR_INDEX")
                    .required(true)
                    .help("The end of the range of keys to generate. This index is not generated."))
            )
            .subcommand(SubCommand::with_name("interop-yaml")
                .about("Loads plain-text secret keys from YAML files. Expects the interop format defined
                       in the ethereum/eth2.0-pm repo.")
                .arg(Arg::with_name("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Path to a YAML file."))
            )
        )
        .subcommand(SubCommand::with_name("sign_block")
            .about("Connects to the beacon server, requests a new block (after providing reveal),\
            and prints the signed block to standard out")
            .arg(Arg::with_name("validator")
                .value_name("VALIDATOR")
                .required(true)
                .help("The pubkey of the validator that should sign the block.")
            )
        )
}
