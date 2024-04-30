use clap::{crate_version, Arg, ArgAction, Command};

pub fn cli_app() -> Command {
    Command::new("simulator")
        .version(crate_version!())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Options for interacting with simulator")
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
                        .action(ArgAction::SetTrue)
                        .help("Continue after checks (default false)"),
                ),
        )
}
