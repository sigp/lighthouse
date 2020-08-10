use crate::config::DEFAULT_HTTP_SERVER;
use clap::{App, Arg};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("validator_client")
        .visible_aliases(&["v", "vc", "validator"])
        .about(
            "When connected to a beacon node, performs the duties of a staked \
                validator (e.g., proposing blocks and attestations).",
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .value_name("NETWORK_ADDRESS")
                .help("Address to connect to BeaconNode.")
                .default_value(&DEFAULT_HTTP_SERVER)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("secrets-dir")
                .long("secrets-dir")
                .value_name("SECRETS_DIRECTORY")
                .help(
                    "The directory which contains the password to unlock the validator \
                    voting keypairs. Each password should be contained in a file where the \
                    name is the 0x-prefixed hex representation of the validators voting public \
                    key. Defaults to ~/.lighthouse/secrets.",
                )
                .takes_value(true),
        )
        .arg(Arg::with_name("auto-register").long("auto-register").help(
            "If present, the validator client will register any new signing keys with \
                       the slashing protection database so that they may be used. WARNING: \
                       enabling the same signing key on multiple validator clients WILL lead to \
                       that validator getting slashed. Only use this flag the first time you run \
                       the validator client, or if you're certain there are no other \
                       nodes using the same key. Automatically enabled unless `--strict` is specified",
        ))
        .arg(
            Arg::with_name("strict-lockfiles")
            .long("strict-lockfiles")
            .help(
                "If present, do not load validators that are guarded by a lockfile. Note: for \
                Eth2 mainnet, this flag will likely be removed and its behaviour will become default."
            )
        )
        .arg(
            Arg::with_name("disable-auto-discover")
            .long("disable-auto-discover")
            .help(
                "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file."
            )
        )
        .arg(
            Arg::with_name("allow-unsynced")
                .long("allow-unsynced")
                .help(
                    "If present, the validator client will still poll for duties if the beacon
                      node is not synced.",
                ),
        )
        // This overwrites the graffiti configured in the beacon node.
        .arg(
            Arg::with_name("graffiti")
                .long("graffiti")
                .help("Specify your custom graffiti to be included in blocks.")
                .value_name("GRAFFITI")
                .takes_value(true)
        )
}
