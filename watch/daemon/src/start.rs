use crate::{config::Config, database::Database, Error};
use eth2::{types::BlockId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use log::{debug, info};
use std::time::Duration;
use types::BeaconBlockHeader;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BLOCKS_PER_CANONICAL_ROOTS_BACKFILL: usize = 1_024;

pub async fn start(config: Config) -> Result<(), Error> {
    let beacon_node_url =
        SensitiveUrl::parse(&config.beacon_node_url).map_err(Error::SensitiveUrl)?;
    let bn = BeaconNodeHttpClient::new(beacon_node_url, Timeouts::set_all(DEFAULT_TIMEOUT));

    let mut db = Database::connect(config).await?;

    let head = get_header(&bn, BlockId::Head)
        .await?
        .ok_or(Error::RemoteHeadUnknown)?;

    // TODO(paul): lock the canonical_roots table?

    debug!("Starting head update with head slot {}", head.slot);
    reverse_fill_canonical_slots(&mut db, &bn, head).await?;

    /*
    if let Some(lowest_slot) = db.lowest_canonical_slot().await?.filter(|slot| *slot != 0) {
        if let Some(earlier_header) = get_header(&bn, BlockId::Slot(lowest_slot - 1)).await? {
            debug!(
                "Starting early slots update with slot {}",
                earlier_header.slot
            );
            reverse_fill_canonical_slots(&mut db, &bn, earlier_header).await?;
        }
    }
    */

    /*
    let highest_slot = db.highest_canonical_slot().await?;
    let lowest_slot = db.lowest_canonical_slot().await?;

    match (highest_slot, lowest_slot) {
        (Some(highest), Some(lowest)) => {
            if head_block.slot >= highest {
                // check slots match.
            } else if head_block.slot < highest {
                // check slots match
            }
        }
        _ => {
            info!("DB canonical slots are not initialized",);
        }
    };
    */

    Ok(())
}

pub async fn reverse_fill_canonical_slots(
    db: &mut Database,
    bn: &BeaconNodeHttpClient,
    mut header: BeaconBlockHeader,
) -> Result<(), Error> {
    let tx = db.transaction().await?;

    /*
    if let Some(root) = Database::get_root_at_canonical_slot(&tx, header.slot).await? {
        if root == header.canonical_root() {
            // If this header is already in the canonical chain, there's nothing to do.
            return Ok(());
        }
    }
    */

    // Remove any descendants which conflict with the new head.
    // Database::delete_canonical_roots_above(&tx, header.slot).await?;

    let mut count = 0;
    let mut prev_slot = header.slot + 1;

    loop {
        let root = header.canonical_root();
        if let Some(known_root) = Database::get_root_at_canonical_slot(&tx, header.slot).await? {
            if known_root == root {
                info!("Reverse fill completed at canonical slot {}", header.slot);
                break;
            }
        } else {
            if count >= MAX_BLOCKS_PER_CANONICAL_ROOTS_BACKFILL {
                info!(
                    "Reverse fill stopped at canonical slot {} with {} slots updated",
                    header.slot, count
                );
                break;
            }
        }

        for slot in header.slot.as_u64()..prev_slot.as_u64() {
            Database::insert_canonical_slot(&tx, slot.into(), root).await?;
            count += 1;
        }

        prev_slot = header.slot;
        header = if let Some(header) = get_header(bn, BlockId::Root(header.parent_root)).await? {
            header
        } else {
            info!("Reverse fill exhausted at canonical slot {}", header.slot);
            break;
        };
    }

    tx.commit().await?;

    Ok(())
}

pub async fn get_header(
    bn: &BeaconNodeHttpClient,
    block_id: BlockId,
) -> Result<Option<BeaconBlockHeader>, Error> {
    Ok(bn
        .get_beacon_headers_block_id(block_id)
        .await?
        .map(|resp| resp.data.header.message))
}
