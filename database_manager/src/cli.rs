pub use clap::Parser;
use clap_utils::get_color_style;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "database_manager",
    alias = "db",
    about = "Manage a beacon node database.",
    styles = get_color_style()
)]
pub struct DatabaseManager {
    #[clap(
        long,
        value_name = "SLOT_COUNT",
        help = "Specifies how often a freezer DB restore point should be stored. \
                Cannot be changed after initialization. \
                [default: 2048 (mainnet) or 64 (minimal)]"
    )]
    pub slots_per_restore_point: Option<u64>,

    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the freezer database."
    )]
    pub freezer_dir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "EPOCHS",
        default_value_t = 0,
        help = "The margin for blob pruning in epochs. The oldest blobs are pruned \
                up until data_availability_boundary - blob_prune_margin_epochs."
    )]
    pub blob_prune_margin_epochs: u64,

    #[clap(
        long,
        value_name = "DIR",
        help = "Data directory for the blobs database."
    )]
    pub blobs_dir: Option<PathBuf>,

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
    #[clap(long, value_name = "VERSION", help = "Schema version to migrate to")]
    pub to: u64,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Inspect raw database values.")]
pub struct Inspect {
    #[clap(long, value_name = "TAG", help = "3-byte column ID (see `DBColumn`)")]
    pub column: String,

    // TODO InspectTarget::VARIANTS
    #[clap(
        long,
        value_name = "TARGET",
        default_value_t = String::from("sizes"),
        help = "Select the type of output to show"
    )]
    pub output: String,

    #[clap(long, value_name = "N", help = "Skip over the first N keys")]
    pub skip: Option<usize>,

    #[clap(long, value_name = "N", help = "Output at most N keys")]
    pub limit: Option<usize>,

    #[clap(
        long,
        conflicts_with = "blobs_db",
        help = "Inspect the freezer DB rather than the hot DB"
    )]
    pub freezer: bool,

    #[clap(
        long,
        conflicts_with = "freezer",
        help = "Inspect the blobs DB rather than the hot DB"
    )]
    pub blobs_db: bool,

    #[clap(
        long,
        value_name = "DIR",
        help = "Base directory for the output files. Defaults to the current directory"
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
                just check that the database is capable of being pruned."
    )]
    pub confirm: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Compact database manually.")]
pub struct Compact {
    #[clap(long, value_name = "TAG", help = "3-byte column ID (see `DBColumn`)")]
    pub column: String,

    #[clap(
        long,
        conflicts_with = "blobs_db",
        help = "Inspect the freezer DB rather than the hot DB"
    )]
    pub freezer: bool,

    #[clap(
        long,
        conflicts_with = "freezer",
        help = "Inspect the blobs DB rather than the hot DB"
    )]
    pub blobs_db: bool,

    #[clap(
        long,
        value_name = "DIR",
        help = "Base directory for the output files. Defaults to the current directory"
    )]
    pub output_dir: Option<PathBuf>,
}
