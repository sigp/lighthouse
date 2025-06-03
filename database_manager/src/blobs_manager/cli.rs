use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Subcommand, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum BlobsManager {
    Verify(VerifyBlobs),
    Import(ImportBlobs),
    Export(ExportBlobs),
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Perform KZG verification for blobs in the database.")]
pub struct VerifyBlobs {
    #[clap(
        long,
        value_name = "URL",
        help = "The beacon node to verify blobs. Defaults to http://localhost:5052",
        display_order = 0
    )]
    pub beacon_node: Option<String>,

    #[clap(
        long,
        value_name = "SLOT",
        help = "The slot at which to begin blob verification. Defaults to the Deneb start slot",
        display_order = 0
    )]
    pub start_slot: Option<u64>,

    #[clap(
        long,
        value_name = "SLOT",
        help = "The slot at which to stop blob verification. Defaults to the latest slot",
        display_order = 0
    )]
    pub end_slot: Option<u64>,

    #[clap(
        long,
        help = "Perform checks even if the beacon node is not synced",
        display_order = 0,
        default_value = "false"
    )]
    pub allow_unsynced: bool,

    #[clap(
        long,
        help = "Skip KZG verification and only perform blob availability checks",
        display_order = 0,
        default_value = "false"
    )]
    pub skip_verification: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Import a batch of blobs in SSZ format into the database.")]
pub struct ImportBlobs {
    #[clap(
        long,
        value_name = "URL",
        help = "The beacon node to import blobs to",
        display_order = 0
    )]
    pub beacon_node: String,

    #[clap(
        long,
        value_name = "FILE",
        help = "Input file containing blobs to import",
        display_order = 0
    )]
    pub input_file: PathBuf,

    #[clap(
        long,
        help = "Skip verification of blobs before import",
        default_value = "false"
    )]
    pub skip_verification: bool,

    #[clap(
        long,
        help = "Attempt import even if the beacon node is not synced",
        display_order = 0,
        default_value = "false"
    )]
    pub allow_unsynced: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Export a batch of blobs in SSZ format from the database.")]
pub struct ExportBlobs {
    #[clap(
        long,
        value_name = "URL",
        help = "The beacon node to export blobs from.",
        display_order = 0
    )]
    pub beacon_node: String,

    #[clap(
        long,
        value_name = "DIR",
        help = "Output dir to export blobs to.",
        display_order = 0
    )]
    pub output_dir: PathBuf,

    #[clap(
        long,
        value_name = "SLOT",
        help = "The slot at which to start exporting blobs from.",
        display_order = 0,
        conflicts_with_all = &["start_epoch", "end_epoch"]
    )]
    pub start_slot: Option<u64>,

    #[clap(
        long,
        value_name = "SLOT",
        help = "The slot at which to stop exporting blobs to (inclusive).",
        display_order = 0,
        conflicts_with_all = &["start_epoch", "end_epoch"]
    )]
    pub end_slot: Option<u64>,

    #[clap(
        long,
        value_name = "EPOCH",
        help = "The epoch at which to start exporting blobs from.",
        display_order = 0,
        conflicts_with_all = &["start_slot", "end_slot"]
    )]
    pub start_epoch: Option<u64>,

    #[clap(
        long,
        value_name = "EPOCH",
        help = "The epoch at which to stop exporting blobs to (inclusive).",
        display_order = 0,
        conflicts_with_all = &["start_slot", "end_slot"]
    )]
    pub end_epoch: Option<u64>,

    #[clap(
        long,
        help = "Attempt export even if the beacon node is not synced",
        display_order = 0,
        default_value = "false"
    )]
    pub allow_unsynced: bool,
}
