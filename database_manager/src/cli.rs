pub use clap::{Arg, ArgAction, Args, Command, FromArgMatches, Parser};
use clap_utils::get_color_style;
use clap_utils::FLAG_HEADER;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use store::hdiff::HierarchyConfig;

use crate::InspectTarget;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "database_manager",
    visible_alias = "db",
    about = "Manage a beacon node database.",
    styles = get_color_style(),
    next_line_help = true,
    term_width = 80,
    disable_help_flag = true,
    disable_help_subcommand = true,
    display_order = 0,
)]
pub struct DatabaseManager {
    #[clap(
        long,
        global = true,
        value_name = "N0,N1,N2,...",
        help = "Specifies the frequency for storing full state snapshots and hierarchical \
                diffs in the freezer DB.",
        default_value_t = HierarchyConfig::default(),
        display_order = 0
    )]
    pub hierarchy_exponents: HierarchyConfig,

    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the freezer database.",
        display_order = 0
    )]
    pub freezer_dir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "EPOCHS",
        default_value_t = 0,
        help = "The margin for blob pruning in epochs. The oldest blobs are pruned \
                up until data_availability_boundary - blob_prune_margin_epochs.",
        display_order = 0
    )]
    pub blob_prune_margin_epochs: u64,

    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the blobs database.",
        display_order = 0
    )]
    pub blobs_dir: Option<PathBuf>,

    #[clap(
        long,
        global = true,
        help = "Prints help information",
        action = clap::ArgAction::HelpLong,
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    help: Option<bool>,

    #[clap(subcommand)]
    pub subcommand: DatabaseManagerSubcommand,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum DatabaseManagerSubcommand {
    Migrate(Migrate),
    Inspect(Inspect),
    Version(Version),
    PrunePayloads(PrunePayloads),
    PruneBlobs(PruneBlobs),
    PruneStates(PruneStates),
    Compact(Compact),
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Migrate the database to a specific schema version.")]
pub struct Migrate {
    #[clap(
        long,
        value_name = "VERSION",
        help = "Schema version to migrate to",
        display_order = 0
    )]
    pub to: u64,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Inspect raw database values.")]
pub struct Inspect {
    #[clap(
        long,
        value_name = "TAG",
        help = "3-byte column ID (see `DBColumn`)",
        display_order = 0
    )]
    pub column: String,

    #[clap(
        long,
        value_enum,
        value_name = "TARGET",
        default_value_t = InspectTarget::ValueSizes,
        help = "Select the type of output to show",
        display_order = 0,
    )]
    pub output: InspectTarget,

    #[clap(
        long,
        value_name = "N",
        help = "Skip over the first N keys",
        display_order = 0
    )]
    pub skip: Option<usize>,

    #[clap(
        long,
        value_name = "N",
        help = "Output at most N keys",
        display_order = 0
    )]
    pub limit: Option<usize>,

    #[clap(
        long,
        conflicts_with = "blobs_db",
        help = "Inspect the freezer DB rather than the hot DB",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub freezer: bool,

    #[clap(
        long,
        conflicts_with = "freezer",
        help = "Inspect the blobs DB rather than the hot DB",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub blobs_db: bool,

    #[clap(
        long,
        value_name = "DIR",
        help = "Base directory for the output files. Defaults to the current directory",
        display_order = 0
    )]
    pub output_dir: Option<PathBuf>,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Display database schema version.", visible_aliases = &["v"])]
pub struct Version {}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Prune finalized execution payloads.",
    alias = "prune_payloads"
)]
pub struct PrunePayloads {}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Prune blobs older than data availability boundary.",
    alias = "prune_blobs"
)]
pub struct PruneBlobs {}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Prune all beacon states from the freezer database.",
    alias = "prune_states"
)]
pub struct PruneStates {
    #[clap(
        long,
        help = "Commit to pruning states irreversably. Without this flag the command will \
                just check that the database is capable of being pruned.",
                help_heading = FLAG_HEADER,
    )]
    pub confirm: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Compact database manually.")]
pub struct Compact {
    #[clap(
        long,
        value_name = "TAG",
        help = "3-byte column ID (see `DBColumn`)",
        display_order = 0
    )]
    pub column: String,

    #[clap(
        long,
        conflicts_with = "blobs_db",
        help = "Inspect the freezer DB rather than the hot DB",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub freezer: bool,

    #[clap(
        long,
        conflicts_with = "freezer",
        help = "Inspect the blobs DB rather than the hot DB",
        display_order = 0,
        help_heading = FLAG_HEADER
    )]
    pub blobs_db: bool,

    #[clap(
        long,
        value_name = "DIR",
        help = "Base directory for the output files. Defaults to the current directory",
        display_order = 0
    )]
    pub output_dir: Option<PathBuf>,
}
