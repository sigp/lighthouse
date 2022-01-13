use clap::ArgMatches;
use clap_utils::lcli_flags::{
    BASE_FEE_PER_GAS_FLAG, EXECUTION_BLOCK_HASH_FLAG, FILE_FLAG, GAS_LIMIT_FLAG, GENESIS_TIME_FLAG,
};
use clap_utils::{parse_optional, parse_required};
use ssz::Encode;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{EthSpec, ExecutionPayloadHeader};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let eth1_block_hash = parse_required(matches, EXECUTION_BLOCK_HASH_FLAG)?;
    let genesis_time = parse_optional(matches, GENESIS_TIME_FLAG)?.unwrap_or(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Unable to get time: {:?}", e))?
            .as_secs(),
    );
    let base_fee_per_gas = parse_required(matches, BASE_FEE_PER_GAS_FLAG)?;
    let gas_limit = parse_required(matches, GAS_LIMIT_FLAG)?;
    let file_name = matches.value_of(FILE_FLAG).ok_or("No file supplied")?;

    let execution_payload_header: ExecutionPayloadHeader<T> = ExecutionPayloadHeader {
        gas_limit,
        base_fee_per_gas,
        timestamp: genesis_time,
        block_hash: eth1_block_hash,
        random: eth1_block_hash,
        ..ExecutionPayloadHeader::default()
    };
    let mut file = File::create(file_name).map_err(|_| "Unable to create file".to_string())?;
    let bytes = execution_payload_header.as_ssz_bytes();
    file.write_all(bytes.as_slice())
        .map_err(|_| "Unable to write to file".to_string())?;
    Ok(())
}
