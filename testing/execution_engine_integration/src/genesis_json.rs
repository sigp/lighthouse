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

/// Modified kiln config
pub fn nethermind_genesis_json() -> Value {
    json!(
        {
            "name": "lighthouse_test_network",
            "engine": {
              "Ethash": {
                "params": {
                  "minimumDifficulty": "0x20000",
                  "difficultyBoundDivisor": "0x800",
                  "durationLimit": "0xd",
                  "blockReward": {
                    "0x0": "0x1BC16D674EC80000"
                  },
                  "homesteadTransition": "0x0",
                  "eip100bTransition": "0x0",
                  "difficultyBombDelays": {}
                }
              }
            },
            "params": {
              "gasLimitBoundDivisor": "0x400",
              "registrar": "0x0000000000000000000000000000000000000000",
              "accountStartNonce": "0x0",
              "maximumExtraDataSize": "0x20",
              "minGasLimit": "0x1388",
              "networkID": "0x1469ca",
              "MergeForkIdTransition": "0x3e8",
              "eip150Transition": "0x0",
              "eip158Transition": "0x0",
              "eip160Transition": "0x0",
              "eip161abcTransition": "0x0",
              "eip161dTransition": "0x0",
              "eip155Transition": "0x0",
              "eip140Transition": "0x0",
              "eip211Transition": "0x0",
              "eip214Transition": "0x0",
              "eip658Transition": "0x0",
              "eip145Transition": "0x0",
              "eip1014Transition": "0x0",
              "eip1052Transition": "0x0",
              "eip1283Transition": "0x0",
              "eip1283DisableTransition": "0x0",
              "eip152Transition": "0x0",
              "eip1108Transition": "0x0",
              "eip1344Transition": "0x0",
              "eip1884Transition": "0x0",
              "eip2028Transition": "0x0",
              "eip2200Transition": "0x0",
              "eip2565Transition": "0x0",
              "eip2929Transition": "0x0",
              "eip2930Transition": "0x0",
              "eip1559Transition": "0x0",
              "eip3198Transition": "0x0",
              "eip3529Transition": "0x0",
              "eip3541Transition": "0x0"
            },
            "genesis": {
              "seal": {
                "ethereum": {
                  "nonce": "0x1234",
                  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
                }
              },
              "difficulty": "0x01",
              "author": "0x0000000000000000000000000000000000000000",
              "timestamp": "0x0",
              "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "extraData": "",
              "gasLimit": "0x1C9C380"
            },
            "accounts": {
              "0x7b8C3a386C0eea54693fFB0DA17373ffC9228139": {
                "balance": "10000000000000000000000000"
              },
              "0xdA2DD7560DB7e212B945fC72cEB54B7D8C886D77": {
                "balance": "10000000000000000000000000"
              },
            },
            "nodes": []
          }
    )
}
