use clap::ArgMatches;
use clap_utils::parse_required;
use environment::Environment;
use eth2::{
    types::{BlockId, PublishBlockRequest, SignedBlockContents},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use eth2_network_config::Eth2NetworkConfig;
use std::sync::Arc;
use std::time::Duration;
use types::EthSpec;

const HTTP_TIMEOUT: Duration = Duration::from_secs(180);

pub fn run<T: EthSpec>(
    env: Environment<T>,
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches<'_>,
) -> Result<(), String> {
    let executor = env.core_context().executor;
    executor
        .handle()
        .ok_or("shutdown in progress")?
        .block_on(async move { run_async::<T>(network_config, matches).await })
        .unwrap();
    Ok(())
}
pub async fn run_async<T: EthSpec>(
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches<'_>,
) -> Result<(), String> {
    let spec = &network_config.chain_spec::<T>()?;
    let source_url: SensitiveUrl = parse_required(matches, "source-url")?;
    let target_url: SensitiveUrl = parse_required(matches, "target-url")?;

    let source = BeaconNodeHttpClient::new(source_url, Timeouts::set_all(HTTP_TIMEOUT));
    let target = BeaconNodeHttpClient::new(target_url, Timeouts::set_all(HTTP_TIMEOUT));

    // 1. Download blocks back from head, looking for common ancestor.
    let mut blocks = vec![];
    let mut next_block_id = BlockId::Head;
    loop {
        println!("downloading {next_block_id:?}");
        let block_from_source = source
            .get_beacon_blocks_ssz::<T>(next_block_id, spec)
            .await
            .unwrap()
            .unwrap();
        let blobs_from_source = source
            .get_blobs::<T>(next_block_id, None)
            .await
            .unwrap()
            .unwrap()
            .data;

        next_block_id = BlockId::Root(block_from_source.parent_root());

        let (kzg_proofs, blobs): (Vec<_>, Vec<_>) = blobs_from_source
            .iter()
            .cloned()
            .map(|sidecar| (sidecar.kzg_proof, sidecar.blob.clone()))
            .unzip();

        let slot = block_from_source.slot();
        let block_contents = SignedBlockContents {
            signed_block: Arc::new(block_from_source),
            kzg_proofs: kzg_proofs.into(),
            blobs: blobs.into(),
        };
        let publish_block_req = PublishBlockRequest::BlockContents(block_contents);
        blocks.push((slot, publish_block_req));

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
        target.post_beacon_blocks(block).await.unwrap();
        println!("success");
    }

    println!("SYNCED!!!!");

    Ok(())
}
