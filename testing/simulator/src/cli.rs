use clap::{Arg, ArgAction, Command};

pub fn cli_app() -> Command {
    Command::new("simulator")
        // .version(crate_version!())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Options for interacting with simulator")
        .subcommand(
            Command::new("eth1-sim")
            .about(
                "Lighthouse Beacon Chain Simulator creates `n` beacon node and validator clients, \
                    each with `v` validators. A deposit contract is deployed at the start of the \
                    simulation using a local `anvil` instance (you must have `anvil` \
                    installed and avaliable on your path). All beacon nodes independently listen \
                    for genesis from the deposit contract, then start operating. \
                    \
                    As the simulation runs, there are checks made to ensure that all components \
                    are running correctly. If any of these checks fail, the simulation will \
                    exit immediately.",
                    )
                    .arg(Arg::new("nodes")
                        .short('n')
                        .long("nodes")
                        .action(ArgAction::Set)
                        .default_value("4")
                        .help("Number of beacon nodes"))
                    .arg(Arg::new("proposer-nodes")
                        .short('p')
                        .long("proposer_nodes")
                        .action(ArgAction::Set)
                        .default_value("2")
                        .help("Number of proposer-only beacon nodes"))
                    .arg(Arg::new("validators_per_node")
                        .short('v')
                        .long("validators_per_node")
                        .action(ArgAction::Set)
                        .default_value("20")
                        .help("Number of validators"))
                    .arg(Arg::new("speed_up_factor")
                        .short('s')
                        .long("speed_up_factor")
                        .action(ArgAction::Set)
                        .default_value("3")
                        .help("Speed up factor. Please use a divisor of 12."))
                    .arg(Arg::new("post-merge")
                        .short('m')
                        .long("post-merge")
                        .action(ArgAction::SetTrue)
                        .help("Simulate the merge transition"))
                    .arg(Arg::new("continue_after_checks")
                        .short('c')
                        .long("continue_after_checks")
                        .action(ArgAction::SetTrue)
                        .help("Continue after checks (default false)"))
        )
        .subcommand(
            Command::new("no-eth1-sim")
            .about("Runs a simulator that bypasses the eth1 chain. Useful for faster testing of
                components that don't rely upon eth1")
                    .arg(Arg::new("nodes")
                        .short('n')
                        .long("nodes")
                        .action(ArgAction::Set)
                        .default_value("4")
                        .help("Number of beacon nodes"))
                    .arg(Arg::new("proposer-nodes")
                        .short('p')
                        .long("proposer_nodes")
                        .action(ArgAction::Set)
                        .default_value("2")
                        .help("Number of proposer-only beacon nodes"))
                    .arg(Arg::new("validators_per_node")
                        .short('v')
                        .long("validators_per_node")
                        .action(ArgAction::Set)
                        .default_value("20")
                        .help("Number of validators"))
                    .arg(Arg::new("speed_up_factor")
                        .short('s')
                        .long("speed_up_factor")
                        .action(ArgAction::Set)
                        .default_value("3")
                        .help("Speed up factor"))
                    .arg(Arg::new("continue_after_checks")
                        .short('c')
                        .long("continue_after_checks")
                        .action(ArgAction::SetTrue)
                        .help("Continue after checks (default false)"))
        )
        .subcommand(
            Command::new("syncing-sim")
                .about("Run the syncing simulation")
                .arg(
                    Arg::new("speedup")
                        .short('s')
                        .long("speedup")
                        .action(ArgAction::Set)
                        .default_value("15")
                        .help("Speed up factor for eth1 blocks and slot production"),
                )
                .arg(
                    Arg::new("initial_delay")
                        .short('i')
                        .long("initial_delay")
                        .action(ArgAction::Set)
                        .default_value("5")
                        .help("Epoch delay for new beacon node to start syncing"),
                )
                .arg(
                    Arg::new("sync_timeout")
                        .long("sync_timeout")
                        .action(ArgAction::Set)
                        .default_value("10")
                        .help("Number of epochs after which newly added beacon nodes must be synced"),
                )
                .arg(
                    Arg::new("strategy")
                        .long("strategy")
                        .action(ArgAction::Set)
                        .default_value("all")
                        .value_parser(["one-node", "two-nodes", "mixed", "all"])
                        .help("Sync verification strategy to run."),
                ),
        )
}
