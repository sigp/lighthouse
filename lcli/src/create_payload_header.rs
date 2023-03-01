use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use ssz::Encode;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{
    EthSpec, ExecutionPayloadHeader, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderEip4844,
    ExecutionPayloadHeaderMerge, ForkName,
};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let eth1_block_hash = parse_required(matches, "execution-block-hash")?;
    let genesis_time = parse_optional(matches, "genesis-time")?.unwrap_or(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Unable to get time: {:?}", e))?
            .as_secs(),
    );
    let base_fee_per_gas = parse_required(matches, "base-fee-per-gas")?;
    let gas_limit = parse_required(matches, "gas-limit")?;
    let file_name = matches.value_of("file").ok_or("No file supplied")?;
    let fork_name: ForkName = parse_optional(matches, "fork")?.unwrap_or(ForkName::Merge);

    let execution_payload_header: ExecutionPayloadHeader<T> = match fork_name {
        ForkName::Base | ForkName::Altair => return Err("invalid fork name".to_string()),
        ForkName::Merge => ExecutionPayloadHeader::Merge(ExecutionPayloadHeaderMerge {
            gas_limit,
            base_fee_per_gas,
            timestamp: genesis_time,
            block_hash: eth1_block_hash,
            prev_randao: eth1_block_hash.into_root(),
            ..ExecutionPayloadHeaderMerge::default()
        }),
        ForkName::Capella => ExecutionPayloadHeader::Capella(ExecutionPayloadHeaderCapella {
            gas_limit,
            base_fee_per_gas,
            timestamp: genesis_time,
            block_hash: eth1_block_hash,
            prev_randao: eth1_block_hash.into_root(),
            ..ExecutionPayloadHeaderCapella::default()
        }),
        ForkName::Eip4844 => ExecutionPayloadHeader::Eip4844(ExecutionPayloadHeaderEip4844 {
            gas_limit,
            base_fee_per_gas,
            timestamp: genesis_time,
            block_hash: eth1_block_hash,
            prev_randao: eth1_block_hash.into_root(),
            ..ExecutionPayloadHeaderEip4844::default()
        }),
    };

    let mut file = File::create(file_name).map_err(|_| "Unable to create file".to_string())?;
    let bytes = execution_payload_header.as_ssz_bytes();
    file.write_all(bytes.as_slice())
        .map_err(|_| "Unable to write to file".to_string())?;
    Ok(())
}
