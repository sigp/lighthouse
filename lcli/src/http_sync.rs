use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::{
    types::{BlockId, ChainSpec, ForkName, PublishBlockRequest, SignedBlockContents},
    BeaconNodeHttpClient, Error, SensitiveUrl, Timeouts,
};
use eth2_network_config::Eth2NetworkConfig;
use ssz::Encode;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use types::EthSpec;

const HTTP_TIMEOUT: Duration = Duration::from_secs(3600);
const DEFAULT_CACHE_DIR: &str = "./cache";

pub fn run<T: EthSpec>(
    env: Environment<T>,
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let executor = env.core_context().executor;
    executor
        .handle()
        .ok_or("shutdown in progress")?
        .block_on(async move { run_async::<T>(network_config, matches).await })
}

pub async fn run_async<T: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = &network_config.chain_spec::<T>()?;
    let source_url: SensitiveUrl = parse_required(matches, "source-url")?;
    let target_url: SensitiveUrl = parse_required(matches, "target-url")?;
    let start_block: BlockId = parse_required(matches, "start-block")?;
    let maybe_common_ancestor_block: Option<BlockId> =
        parse_optional(matches, "known–common-ancestor")?;
    let cache_dir_path: PathBuf =
        parse_optional(matches, "block-cache-dir")?.unwrap_or(DEFAULT_CACHE_DIR.into());

    let source = BeaconNodeHttpClient::new(source_url, Timeouts::set_all(HTTP_TIMEOUT));
    let target = BeaconNodeHttpClient::new(target_url, Timeouts::set_all(HTTP_TIMEOUT));

    if !cache_dir_path.exists() {
        fs::create_dir_all(&cache_dir_path)
            .map_err(|e| format!("Unable to create block cache dir: {:?}", e))?;
    }

    // 1. Download blocks back from head, looking for common ancestor.
    let mut blocks = vec![];
    let mut next_block_id = start_block;
    loop {
        println!("downloading {next_block_id:?}");

        let publish_block_req =
            get_block_from_source::<T>(&source, next_block_id, spec, &cache_dir_path).await;
        let block = publish_block_req.signed_block();

        next_block_id = BlockId::Root(block.parent_root());
        blocks.push((block.slot(), publish_block_req));

        if let Some(ref common_ancestor_block) = maybe_common_ancestor_block {
            if common_ancestor_block == &next_block_id {
                println!("reached known common ancestor: {next_block_id:?}");
                break;
            }
        }

        let block_exists_in_target = target
            .get_beacon_blocks_ssz::<T>(next_block_id, spec)
            .await
            .unwrap()
            .is_some();
        if block_exists_in_target {
            println!("common ancestor found: {next_block_id:?}");
            break;
        }
    }

    // 2. Apply blocks to target.
    for (slot, block) in blocks.iter().rev() {
        println!("posting block at slot {slot}");
        if let Err(e) = target.post_beacon_blocks(block).await {
            if let Error::ServerMessage(ref e) = e {
                if e.code == 202 {
                    println!("duplicate block detected while posting block at slot {slot}");
                    continue;
                }
            }
            return Err(format!("error posting {slot}: {e:?}"));
        } else {
            println!("success");
        }
    }

    println!("SYNCED!!!!");

    Ok(())
}

async fn get_block_from_source<T: EthSpec>(
    source: &BeaconNodeHttpClient,
    block_id: BlockId,
    spec: &ChainSpec,
    cache_dir_path: &Path,
) -> PublishBlockRequest<T> {
    let mut cache_path = cache_dir_path.join(format!("block_{block_id}"));

    if cache_path.exists() {
        let mut f = File::open(&cache_path).unwrap();
        let mut bytes = vec![];
        f.read_to_end(&mut bytes).unwrap();
        PublishBlockRequest::from_ssz_bytes(&bytes, ForkName::Deneb).unwrap()
    } else {
        let block_from_source = source
            .get_beacon_blocks_ssz::<T>(block_id, spec)
            .await
            .unwrap()
            .unwrap();
        let blobs_from_source = source
            .get_blobs::<T>(block_id, None)
            .await
            .unwrap()
            .unwrap()
            .data;

        let (kzg_proofs, blobs): (Vec<_>, Vec<_>) = blobs_from_source
            .iter()
            .cloned()
            .map(|sidecar| (sidecar.kzg_proof, sidecar.blob.clone()))
            .unzip();

        let block_root = block_from_source.canonical_root();
        let block_contents = SignedBlockContents {
            signed_block: Arc::new(block_from_source),
            kzg_proofs: kzg_proofs.into(),
            blobs: blobs.into(),
        };
        let publish_block_req = PublishBlockRequest::BlockContents(block_contents);

        cache_path = cache_dir_path.join(format!("block_{block_root:?}"));
        let mut f = File::create(&cache_path).unwrap();
        f.write_all(&publish_block_req.as_ssz_bytes()).unwrap();

        publish_block_req
    }
}
