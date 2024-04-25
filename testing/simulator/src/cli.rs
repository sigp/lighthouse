use clap::{crate_version, Arg, ArgAction, Command};

pub fn cli_app() -> Command {
    Command::new("simulator")
        .version(crate_version!())
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
                )
            .subcommand(
                Command::new("basic-sim")
                .about(
                    "Runs a Beacon Chain simulation with `n` beacon node and validator clients, \
                    each with `v` validators. \
                    The simulation runs with a post-Merge Genesis using `mock-el`. \
                    As the simulation runs, there are checks made to ensure that all components \
                    are running correctly. If any of these checks fail, the simulation will \
                    exit immediately.",
                )
                .arg(
                    Arg::new("nodes")
                        .short('n')
                        .long("nodes")
                        .action(ArgAction::Set)
                        .default_value("3")
                        .help("Number of beacon nodes"),
                )
                .arg(
                    Arg::new("proposer-nodes")
                        .short('p')
                        .long("proposer-nodes")
                        .action(ArgAction::Set)
                        .default_value("3")
                        .help("Number of proposer-only beacon nodes"),
                )
                .arg(
                    Arg::new("validators-per-node")
                        .short('v')
                        .long("validators-per-node")
                        .action(ArgAction::Set)
                        .default_value("20")
                        .help("Number of validators"),
                )
                .arg(
                    Arg::new("speed-up-factor")
                        .short('s')
                        .long("speed-up-factor")
                        .action(ArgAction::Set)
                        .default_value("3")
                        .help("Speed up factor. Please use a divisor of 12."),
                )
                .arg(
                    Arg::new("debug-level")
                        .short('d')
                        .long("debug-level")
                        .action(ArgAction::Set)
                        .default_value("debug")
                        .help("Set the severity level of the logs."),
                )
                .arg(
                    Arg::new("continue-after-checks")
                        .short('c')
                        .long("continue_after_checks")
                        .action(ArgAction::SetTrue)
                        .help("Continue after checks (default false)"),
                ),
        )
        .subcommand(
            Command::new("fallback-sim")
                .about(
                    "Runs a Beacon Chain simulation with `c` validator clients where each VC is \
                    connected to `b` beacon nodes with `v` validators. \
                    During the simulation, all but the last connected BN for each VC are \
                    disconnected from the execution layer, which causes the VC to fallback to the \
                    single remaining BN. \
                    At the end of the simulation, there are checks made to ensure that all VCs  \
                    efficiently performed this fallback, within a certain tolerance. \
                    Otherwise, the simulation will exit and an error will be reported.",
                )
                .arg(
                    Arg::new("vc-count")
                        .short('c')
                        .long("vc-count")
                        .action(ArgAction::Set)
                        .default_value("3")
                        .help("Number of validator clients."),
                )
                .arg(
                    Arg::new("bns-per-vc")
                        .short('b')
                        .long("bns-per-vc")
                        .action(ArgAction::Set)
                        .default_value("2")
                        .help("Number of beacon nodes per validator client."),
                )
                .arg(
                    Arg::new("validators-per-vc")
                        .short('v')
                        .long("validators-per-vc")
                        .action(ArgAction::Set)
                        .default_value("20")
                        .help("Number of validators per client."),
                )
                .arg(
                    Arg::new("speed-up-factor")
                        .short('s')
                        .long("speed-up-factor")
                        .action(ArgAction::Set)
                        .default_value("3")
                        .help("Speed up factor. Please use a divisor of 12."),
                )
                .arg(
                    Arg::new("debug-level")
                        .short('d')
                        .long("debug-level")
                        .action(ArgAction::Set)
                        .default_value("debug")
                        .help("Set the severity level of the logs."),
                )
                .arg(
                    Arg::new("continue-after-checks")
                        .short('c')
                        .long("continue_after_checks")
                        .action(ArgAction::Set)
                        .help("Continue after checks (default false)"),
                )
            )
        )
}
