pub use clap::{FromArgMatches, Parser};
use clap_utils::FLAG_HEADER;
use clap_utils::get_color_style;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "lean_validator_node",
    visible_aliases = &["l", "ln", "lean_node"],
    about = "lean node follows the lean consensus for ethereum chain",
    styles = get_color_style(),
    next_line_help = true,
    term_width = 80,
    disable_help_flag = true,
    disable_help_subcommand = true,
    display_order = 0,
)]
pub struct LeanNode {
    #[clap(
        long,
        alias = "validator-dir",
        value_name = "VALIDATORS_DIR",
        conflicts_with = "datadir",
        help = "The directory which contains the validator keystores, deposit data for \
                each validator along with the common slashing protection database \
                and the validator_definitions.yml",
        display_order = 0
    )]
    pub validators_dir: Option<PathBuf>,

    #[clap(
        long,
        help = "If present, do not attempt to discover new validators in the validators-dir. Validators \
                will need to be manually added to the validator_definitions.yml file.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub disable_auto_discover: bool,

    #[clap(
        long,
        help = "Disable the performance of attestation duties (and sync committee duties). This \
                flag should only be used in emergencies to prioritise block proposal duties.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub disable_attesting: bool,

    /* Prometheus metrics HTTP server related arguments */
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default.",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub metrics: bool,
}
