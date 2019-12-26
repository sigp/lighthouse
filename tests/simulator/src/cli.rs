use clap::{App, Arg, SubCommand};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("simulator")
        .about("Options for interacting with simulator")
        .subcommand(
            SubCommand::with_name("beacon-chain-sim")
                .about("Run the beacon chain simulation")
                .arg(
                    Arg::with_name("nodes")
                        .short("n")
                        .long("nodes")
                        .value_name("NUM_NODES")
                        .takes_value(true)
                        .default_value("4")
                        .help("Number of beacon nodes instances to spin up"),
                )
                .arg(
                    Arg::with_name("validators")
                        .short("v")
                        .long("validators")
                        .value_name("VALIDATORS_PER_NODE")
                        .takes_value(true)
                        .default_value("20")
                        .help("Number of validators per node"),
                )
                .arg(
                    Arg::with_name("log-level")
                        .short("l")
                        .long("log-level")
                        .value_name("LOG_LEVEL")
                        .takes_value(true)
                        .default_value("debug")
                        .help("Logging level"),
                )
                .arg(
                    Arg::with_name("speedup")
                        .short("s")
                        .long("speedup")
                        .value_name("SPEEDUP")
                        .takes_value(true)
                        .default_value("4")
                        .help("Speed up factor for eth1 blocks and slot production"),
                ),
        )
        .subcommand(
            SubCommand::with_name("syncing-sim")
                .about("Run the syncing simulation")
                .arg(
                    Arg::with_name("strategy")
                        .short("s")
                        .long("strategy")
                        .value_name("strategy")
                        .takes_value(true)
                        .default_value("0")
                        .help("Number of beacon nodes instances to spin up"),
                )
                .arg(
                    Arg::with_name("speedup")
                        .short("s")
                        .long("speedup")
                        .value_name("SPEEDUP")
                        .takes_value(true)
                        .default_value("15")
                        .help("Speed up factor for eth1 blocks and slot production"),
                )
                .arg(
                    Arg::with_name("epochs")
                        .short("e")
                        .long("epochs")
                        .value_name("EPOCHS")
                        .takes_value(true)
                        .default_value("3")
                        .help("Epoch delay for new beacon node to start syncing"),
                ),
        )
}
