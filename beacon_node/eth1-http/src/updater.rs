use crate::block_cache::{Error as Eth1Error, Eth1DataCache, Eth1Snapshot};
use crate::http::{get_block, get_block_number, get_deposit_count, get_deposit_root, Block};
use futures::{future, prelude::*, stream, Future};
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use std::ops::Deref;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use types::Hash256;

const MAX_BLOCKS_PER_REQUEST: usize = 100;

const BLOCK_NUMBER_TIMEOUT_MILLIS: u64 = 1_000;
const GET_BLOCK_TIMEOUT_MILLIS: u64 = 1_000;
const GET_DEPOSIT_ROOT_TIMEOUT_MILLIS: u64 = 1_000;
const GET_DEPOSIT_COUNT_TIMEOUT_MILLIS: u64 = 1_000;

pub enum Error {
    RemoteNotSynced {
        local_highest_block: u64,
        remote_highest_block: u64,
    },
    BlockDownloadFailed(String),
    GetBlockNumberFailed(String),
    GetDepositRootFailed(String),
    GetDepositCountFailed(String),
    FailedToInsertEth1Snapshot(Eth1Error),
}

pub enum Eth1UpdateResult {
    Success {
        blocks_imported: usize,
        head_block_number: u64,
    },
    UpdateInProgress,
}

/*
struct UpdateTarget<T> {
    update_in_progress: bool,
    item: T,
}

impl<T> Deref for UpdateTarget<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.item
    }
}
*/

pub struct Eth1Cache {
    endpoint: String,
    deposit_contract_address: String,
    eth1_data_cache: RwLock<Eth1DataCache>,
    eth1_data_cache_updating: RwLock<bool>,
}

impl Eth1Cache {
    pub fn try_set_lock(&self, lock: &RwLock<bool>) -> bool {
        let read = self.eth1_data_cache_updating.upgradable_read();
        if *read == false {
            let mut write = RwLockUpgradableReadGuard::upgrade(read);
            *write = true;
            true
        } else {
            false
        }
    }

    pub fn update_eth1_data_cache<'a>(
        &'a self,
    ) -> Box<dyn Future<Item = Eth1UpdateResult, Error = Error> + 'a> {
        if self.try_set_lock(&self.eth1_data_cache_updating) {
            let f = get_block_number(
                &self.endpoint,
                Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS),
            )
            .map_err(|e| Error::GetBlockNumberFailed(e))
            .and_then(move |remote_highest_block| {
                let local_highest_block = self
                    .eth1_data_cache
                    .read()
                    .next_block_number()
                    .saturating_sub(1);

                if local_highest_block > remote_highest_block {
                    Err(Error::RemoteNotSynced {
                        local_highest_block,
                        remote_highest_block,
                    })
                } else {
                    Ok(local_highest_block..remote_highest_block)
                }
            })
            .and_then(move |required_block_numbers| {
                download_eth1_snapshots(
                    self.endpoint.clone(),
                    self.deposit_contract_address.clone(),
                    required_block_numbers,
                )
                .collect()
            })
            .and_then(move |snapshots| {
                let blocks_imported = snapshots.len();
                snapshots
                    .into_iter()
                    .map(|snapshot| {
                        self.eth1_data_cache
                            .write()
                            .insert(snapshot)
                            .map_err(|e| Error::FailedToInsertEth1Snapshot(e))
                    })
                    .collect::<Result<_, Error>>()?;

                Ok(Eth1UpdateResult::Success {
                    blocks_imported,
                    head_block_number: self
                        .eth1_data_cache
                        .read()
                        .next_block_number()
                        .saturating_sub(1),
                })
            })
            .then(move |result| {
                *(self.eth1_data_cache_updating.write()) = false;
                result
            });

            Box::new(f)
        } else {
            Box::new(future::ok::<Eth1UpdateResult, Error>(
                Eth1UpdateResult::UpdateInProgress,
            ))
        }
    }
}

fn download_eth1_snapshots(
    endpoint: String,
    address: String,
    block_numbers: Range<u64>,
) -> impl Stream<Item = Eth1Snapshot, Error = Error> {
    stream::unfold(
        block_numbers.into_iter(),
        move |mut block_numbers| match block_numbers.next() {
            Some(block_number) => Some(
                get_block(
                    &endpoint,
                    block_number,
                    Duration::from_millis(GET_BLOCK_TIMEOUT_MILLIS),
                )
                .map_err(|e| Error::BlockDownloadFailed(e))
                .join3(
                    get_deposit_root(
                        &endpoint,
                        &address,
                        block_number,
                        Duration::from_millis(GET_DEPOSIT_ROOT_TIMEOUT_MILLIS),
                    )
                    .map_err(|e| Error::GetDepositRootFailed(e)),
                    get_deposit_count(
                        &endpoint,
                        &address,
                        block_number,
                        Duration::from_millis(GET_DEPOSIT_COUNT_TIMEOUT_MILLIS),
                    )
                    .map_err(|e| Error::GetDepositCountFailed(e)),
                )
                .map(|v| (v, block_numbers)),
            ),
            None => None,
        },
    )
    .map(|(block, deposit_root, deposit_count)| Eth1Snapshot {
        block,
        deposit_root,
        deposit_count,
    })
}
