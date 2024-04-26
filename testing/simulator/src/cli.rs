use clap::{App, Arg, SubCommand};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("simulator")
        .version(crate_version!())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Options for interacting with simulator")
        .subcommand(
            SubCommand::with_name("basic-sim")
                .about(
                    "Runs a Beacon Chain simulation with `n` beacon node and validator clients, \
                    each with `v` validators. \
                    The simulation runs with a post-Merge Genesis using `mock-el`. \
                    As the simulation runs, there are checks made to ensure that all components \
                    are running correctly. If any of these checks fail, the simulation will \
                    exit immediately.",
                )
                .arg(
                    Arg::with_name("nodes")
                        .short("n")
                        .long("nodes")
                        .takes_value(true)
                        .default_value("3")
                        .help("Number of beacon nodes"),
                )
                .arg(
                    Arg::with_name("proposer-nodes")
                        .short("p")
                        .long("proposer-nodes")
                        .takes_value(true)
                        .default_value("3")
                        .help("Number of proposer-only beacon nodes"),
                )
                .arg(
                    Arg::with_name("validators-per-node")
                        .short("v")
                        .long("validators-per-node")
                        .takes_value(true)
                        .default_value("20")
                        .help("Number of validators"),
                )
                .arg(
                    Arg::with_name("speed-up-factor")
                        .short("s")
                        .long("speed-up-factor")
                        .takes_value(true)
                        .default_value("3")
                        .help("Speed up factor. Please use a divisor of 12."),
                )
                .arg(
                    Arg::with_name("debug-level")
                        .short("d")
                        .long("debug-level")
                        .takes_value(true)
                        .default_value("debug")
                        .help("Set the severity level of the logs."),
                )
                .arg(
                    Arg::with_name("continue-after-checks")
                        .short("c")
                        .long("continue_after_checks")
                        .takes_value(false)
                        .help("Continue after checks (default false)"),
                ),
        )
        .subcommand(
            SubCommand::with_name("fallback-sim")
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
                    Arg::with_name("vc-count")
                        .short("c")
                        .long("vc-count")
                        .takes_value(true)
                        .default_value("3")
                        .help("Number of validator clients."),
                )
                .arg(
                    Arg::with_name("bns-per-vc")
                        .short("b")
                        .long("bns-per-vc")
                        .takes_value(true)
                        .default_value("2")
                        .help("Number of beacon nodes per validator client."),
                )
                .arg(
                    Arg::with_name("validators-per-vc")
                        .short("v")
                        .long("validators-per-vc")
                        .takes_value(true)
                        .default_value("20")
                        .help("Number of validators per client."),
                )
                .arg(
                    Arg::with_name("speed-up-factor")
                        .short("s")
                        .long("speed-up-factor")
                        .takes_value(true)
                        .default_value("3")
                        .help("Speed up factor. Please use a divisor of 12."),
                )
                .arg(
                    Arg::with_name("debug-level")
                        .short("d")
                        .long("debug-level")
                        .takes_value(true)
                        .default_value("debug")
                        .help("Set the severity level of the logs."),
                )
                .arg(
                    Arg::with_name("continue-after-checks")
                        .short("c")
                        .long("continue_after_checks")
                        .takes_value(false)
           .help("Number of validators per client"))
                .arg(Arg::with_name("speed_up_factor")
                    .short("s")
                    .long("speed_up_factor")
                    .takes_value(true)
                    .default_value("3")
                    .help("Speed up factor. Please use a divisor of 12."))
                .arg(Arg::with_name("continue_after_checks")
                    .short("c")
                    .long("continue_after_checks")
                    .takes_value(false)
                    .help("Continue after checks (default false)")
                        .help("Continue after checks (default false)"),
                ),
        )
}
