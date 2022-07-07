use serde_json::{json, Value};

/// Sourced from:
///
/// https://notes.ethereum.org/rmVErCfCRPKGqGkUe89-Kg
pub fn geth_genesis_json() -> Value {
    json!({
        "config": {
            "chainId":1,
            "homesteadBlock":0,
            "eip150Block":0,
            "eip155Block":0,
            "eip158Block":0,
            "byzantiumBlock":0,
            "constantinopleBlock":0,
            "petersburgBlock":0,
            "istanbulBlock":0,
            "muirGlacierBlock":0,
            "berlinBlock":0,
            "londonBlock":0,
            "clique": {
                "period": 5,
                "epoch": 30000
            },
            "terminalTotalDifficulty":0
        },
        "nonce":"0x42",
        "timestamp":"0x0",
        "extraData":"0x0000000000000000000000000000000000000000000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "gasLimit":"0x1C9C380",
        "difficulty":"0x400000000",
        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase":"0x0000000000000000000000000000000000000000",
        "alloc":{
            "0x7b8C3a386C0eea54693fFB0DA17373ffC9228139": {
                "balance": "10000000000000000000000000"
              },
              "0xdA2DD7560DB7e212B945fC72cEB54B7D8C886D77": {
                "balance": "10000000000000000000000000"
              },
        },
        "number":"0x0",
        "gasUsed":"0x0",
        "parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "baseFeePerGas":"0x7"
    })
}
