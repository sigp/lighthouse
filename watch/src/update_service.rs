use crate::database::{Config, Database, Error, Transaction};
use eth2::{types::BlockId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use log::{debug, info};
use std::time::Duration;
use types::{BeaconBlockHeader, EthSpec, Hash256, Slot};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
pub const BACKFILL_SLOT_COUNT: usize = 64;

pub async fn run_once<T: EthSpec>(config: &Config) -> Result<(), Error> {
    let beacon_node_url =
        SensitiveUrl::parse(&config.beacon_node_url).map_err(Error::SensitiveUrl)?;
    let bn = BeaconNodeHttpClient::new(beacon_node_url, Timeouts::set_all(DEFAULT_TIMEOUT));

    let mut db = Database::connect(&config).await?;

    // TODO(paul): lock the canonical slots and epochs tables?

    perform_head_update::<T>(&mut db, &bn).await?;
    perform_backfill::<T>(&mut db, &bn).await?;
    update_unknown_blocks(&mut db, &bn).await?;

    Ok(())
}

pub async fn update_unknown_blocks<'a>(
    db: &mut Database,
    bn: &BeaconNodeHttpClient,
) -> Result<(), Error> {
    let tx = db.transaction().await?;

    for root in Database::unknown_canonical_blocks(&tx, BACKFILL_SLOT_COUNT as i64).await? {
        if let Some(header) = get_header(bn, BlockId::Root(root)).await? {
            Database::insert_canonical_header_if_not_exists(&tx, &header, root).await?;
        }
    }

    tx.commit().await?;

    Ok(())
}

pub async fn perform_head_update<'a, T: EthSpec>(
    db: &mut Database,
    bn: &BeaconNodeHttpClient,
) -> Result<(), Error> {
    // Load the head from the beacon node.
    let head = get_header(&bn, BlockId::Head)
        .await?
        .ok_or(Error::RemoteHeadUnknown)?;
    let head_root = head.canonical_root();

    debug!("Starting head update with head slot {}", head.slot);

    let tx = db.transaction().await?;

    // Remove all canonical roots with a slot higher than the head. This removes prunes
    // non-canonical blocks when there is a re-org to a block with a lower slot.
    if let Some(root) = Database::get_root_at_canonical_slot(&tx, head.slot).await? {
        if root != head.canonical_root() {
            Database::delete_canonical_roots_above::<T>(&tx, head.slot).await?;
        }
    }

    // Assume that the slot after the head will not be a skip slot.
    let next_non_skipped_block = head.slot + 1;
    // Don't backfill more than minimally required.
    let backfill_block_count = 1;

    // Replace all conflicting ancestors. Perform partial backfill.
    reverse_fill_canonical_slots::<T>(
        &tx,
        &bn,
        next_non_skipped_block,
        head,
        head_root,
        backfill_block_count,
    )
    .await?;
    tx.commit().await?;

    Ok(())
}

pub async fn perform_backfill<'a, T: EthSpec>(
    db: &mut Database,
    bn: &BeaconNodeHttpClient,
) -> Result<(), Error> {
    let tx = db.transaction().await?;

    dbg!("this");
    if let Some(lowest_slot) = Database::lowest_canonical_slot(&tx)
        .await?
        .filter(|lowest_slot| *lowest_slot != 0)
    {
        dbg!(lowest_slot);
        if let Some(header) = get_header(&bn, BlockId::Slot(lowest_slot - 1)).await? {
            let header_root = header.canonical_root();
            reverse_fill_canonical_slots::<T>(
                &tx,
                &bn,
                lowest_slot,
                header,
                header_root,
                BACKFILL_SLOT_COUNT,
            )
            .await?;
        }
    }

    tx.commit().await?;

    Ok(())
}

pub async fn reverse_fill_canonical_slots<'a, T: EthSpec>(
    tx: &'a Transaction<'a>,
    bn: &BeaconNodeHttpClient,
    mut next_non_skipped_block: Slot,
    mut header: BeaconBlockHeader,
    mut header_root: Hash256,
    max_count: usize,
) -> Result<(), Error> {
    let mut count = 0;

    loop {
        if let Some(known_root) = Database::get_root_at_canonical_slot(&tx, header.slot).await? {
            if known_root == header_root {
                info!("Reverse fill completed at canonical slot {}", header.slot);
                break;
            }
        } else {
            if count >= max_count {
                info!(
                    "Reverse fill stopped at canonical slot {} with {} slots updated",
                    header.slot, count
                );
                break;
            }
        }

        for slot in header.slot.as_u64()..next_non_skipped_block.as_u64() {
            Database::insert_canonical_root::<T>(&tx, slot.into(), header_root).await?;
            count += 1;
        }

        next_non_skipped_block = header.slot;
        header = if let Some(header) = get_header(bn, BlockId::Root(header.parent_root)).await? {
            header_root = header.canonical_root();
            header
        } else {
            info!("Reverse fill exhausted at canonical slot {}", header.slot);
            break;
        };
    }

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
