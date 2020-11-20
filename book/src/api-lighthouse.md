# Lighthouse Non-Standard APIs

Lighthouse fully supports the standardization efforts at
[github.com/ethereum/eth2.0-APIs](https://github.com/ethereum/eth2.0-APIs),
however sometimes development requires additional endpoints that shouldn't
necessarily be defined as a broad-reaching standard.  Such endpoints are placed
behind the `/lighthouse` path.

The endpoints behind the `/lighthouse` path are:

- Not intended to be stable.
- Not guaranteed to be safe.
- For testing and debugging purposes only.

Although we don't recommend that users rely on these endpoints, we
document them briefly so they can be utilized by developers and
researchers.

### `/lighthouse/health`

*Presently only available on Linux.*

```bash
curl -X GET "http://localhost:5052/lighthouse/health" -H  "accept: application/json" | jq
```

```json
{
  "data": {
    "pid": 1728254,
    "pid_num_threads": 47,
    "pid_mem_resident_set_size": 510054400,
    "pid_mem_virtual_memory_size": 3963158528,
    "sys_virt_mem_total": 16715530240,
    "sys_virt_mem_available": 4065374208,
    "sys_virt_mem_used": 11383402496,
    "sys_virt_mem_free": 1368662016,
    "sys_virt_mem_percent": 75.67906,
    "sys_loadavg_1": 4.92,
    "sys_loadavg_5": 5.53,
    "sys_loadavg_15": 5.58
  }
}
```

### `/lighthouse/syncing`

```bash
curl -X GET "http://localhost:5052/lighthouse/syncing" -H  "accept: application/json" | jq
```

```json
{
  "data": {
    "SyncingFinalized": {
      "start_slot": 3104,
      "head_slot": 343744,
      "head_root": "0x1b434b5ed702338df53eb5e3e24336a90373bb51f74b83af42840be7421dd2bf"
    }
  }
}
```

### `/lighthouse/peers`

```bash
curl -X GET "http://localhost:5052/lighthouse/peers" -H  "accept: application/json" | jq
```

```json
[
  {
    "peer_id": "16Uiu2HAmA9xa11dtNv2z5fFbgF9hER3yq35qYNTPvN7TdAmvjqqv",
    "peer_info": {
      "_status": "Healthy",
      "score": {
        "score": 0
      },
      "client": {
        "kind": "Lighthouse",
        "version": "v0.2.9-1c9a055c",
        "os_version": "aarch64-linux",
        "protocol_version": "lighthouse/libp2p",
        "agent_string": "Lighthouse/v0.2.9-1c9a055c/aarch64-linux"
      },
      "connection_status": {
        "status": "disconnected",
        "connections_in": 0,
        "connections_out": 0,
        "last_seen": 1082,
        "banned_ips": []
      },
      "listening_addresses": [
        "/ip4/80.109.35.174/tcp/9000",
        "/ip4/127.0.0.1/tcp/9000",
        "/ip4/192.168.0.73/tcp/9000",
        "/ip4/172.17.0.1/tcp/9000",
        "/ip6/::1/tcp/9000"
      ],
      "sync_status": {
        "Advanced": {
          "info": {
            "status_head_slot": 343829,
            "status_head_root": "0xe34e43efc2bb462d9f364bc90e1f7f0094e74310fd172af698b5a94193498871",
            "status_finalized_epoch": 10742,
            "status_finalized_root": "0x1b434b5ed702338df53eb5e3e24336a90373bb51f74b83af42840be7421dd2bf"
          }
        }
      },
      "meta_data": {
        "seq_number": 160,
        "attnets": "0x0000000800000080"
      }
    }
  }
]
```

### `/lighthouse/peers/connected`

```bash
curl -X GET "http://localhost:5052/lighthouse/peers/connected" -H  "accept: application/json" | jq
```

```json
[
  {
    "peer_id": "16Uiu2HAkzJC5TqDSKuLgVUsV4dWat9Hr8EjNZUb6nzFb61mrfqBv",
    "peer_info": {
      "_status": "Healthy",
      "score": {
        "score": 0
      },
      "client": {
        "kind": "Lighthouse",
        "version": "v0.2.8-87181204+",
        "os_version": "x86_64-linux",
        "protocol_version": "lighthouse/libp2p",
        "agent_string": "Lighthouse/v0.2.8-87181204+/x86_64-linux"
      },
      "connection_status": {
        "status": "connected",
        "connections_in": 1,
        "connections_out": 0,
        "last_seen": 0,
        "banned_ips": []
      },
      "listening_addresses": [
        "/ip4/34.204.178.218/tcp/9000",
        "/ip4/127.0.0.1/tcp/9000",
        "/ip4/172.31.67.58/tcp/9000",
        "/ip4/172.17.0.1/tcp/9000",
        "/ip6/::1/tcp/9000"
      ],
      "sync_status": "Unknown",
      "meta_data": {
        "seq_number": 1819,
        "attnets": "0xffffffffffffffff"
      }
    }
  }
]
```

### `/lighthouse/proto_array`

```bash
curl -X GET "http://localhost:5052/lighthouse/proto_array" -H  "accept: application/json" | jq
```

*Example omitted for brevity.*

### `/lighthouse/validator_inclusion/{epoch}/{validator_id}`

See [Validator Inclusion APIs](./validator-inclusion.md).

### `/lighthouse/validator_inclusion/{epoch}/global`

See [Validator Inclusion APIs](./validator-inclusion.md).

### `/lighthouse/eth1/syncing`

Returns information regarding the Eth1 network, as it is required for use in
Eth2

#### Fields

- `head_block_number`, `head_block_timestamp`: the block number and timestamp
from the very head of the Eth1 chain. Useful for understanding the immediate
health of the Eth1 node that the beacon node is connected to.
- `latest_cached_block_number` & `latest_cached_block_timestamp`: the block
number and timestamp of the latest block we have in our block cache.
	- For correct Eth1 voting this timestamp should be later than the
`voting_period_start_timestamp`.
- `voting_period_start_timestamp`: the start of the period where block
	producers must include votes for blocks in the Eth1 chain. Provided for
	reference.
- `eth1_node_sync_status_percentage` (float): An estimate of how far the head of the
	Eth1 node is from the head of the Eth1 chain.
	- `100.0` indicates a fully synced Eth1 node.
	- `0.0` indicates an Eth1 node that has not verified any blocks past the
		genesis block.
- `lighthouse_is_cached_and_ready`: Is set to `true` if the caches in the
	beacon node are ready for block production.
	- This value might be set to
	`false` whilst `eth1_node_sync_status_percentage == 100.0` if the beacon
	node is still building its internal cache.
	- This value might be set to `true` whilst
	`eth1_node_sync_status_percentage < 100.0` since the cache only cares
	about blocks a certain distance behind the head.

#### Example

```bash
curl -X GET "http://localhost:5052/lighthouse/eth1/syncing" -H  "accept: application/json" | jq
```

```json
{
  "data": {
    "head_block_number": 3611806,
    "head_block_timestamp": 1603249317,
    "latest_cached_block_number": 3610758,
    "latest_cached_block_timestamp": 1603233597,
    "voting_period_start_timestamp": 1603228632,
    "eth1_node_sync_status_percentage": 100,
    "lighthouse_is_cached_and_ready": true
  }
}
```

### `/lighthouse/eth1/block_cache`

Returns a list of all the Eth1 blocks in the Eth1 voting cache.

#### Example

```bash
curl -X GET "http://localhost:5052/lighthouse/eth1/block_cache" -H  "accept: application/json" | jq
```

```json
{
  "data": [
    {
      "hash": "0x3a17f4b7ae4ee57ef793c49ebc9c06ff85207a5e15a1d0bd37b68c5ef5710d7f",
      "timestamp": 1603173338,
      "number": 3606741,
      "deposit_root": "0xd24920d936e8fb9b67e93fd126ce1d9e14058b6d82dcf7d35aea46879fae6dee",
      "deposit_count": 88911
    },
    {
      "hash": "0x78852954ea4904e5f81038f175b2adefbede74fbb2338212964405443431c1e7",
      "timestamp": 1603173353,
      "number": 3606742,
      "deposit_root": "0xd24920d936e8fb9b67e93fd126ce1d9e14058b6d82dcf7d35aea46879fae6dee",
      "deposit_count": 88911
    }
  ]
}
```

### `/lighthouse/eth1/deposit_cache`

Returns a list of all cached logs from the deposit contract.

#### Example

```bash
curl -X GET "http://localhost:5052/lighthouse/eth1/deposit_cache" -H  "accept: application/json" | jq
```

```json
{
  "data": [
    {
      "deposit_data": {
        "pubkey": "0xae9e6a550ac71490cdf134533b1688fcbdb16f113d7190eacf4f2e9ca6e013d5bd08c37cb2bde9bbdec8ffb8edbd495b",
        "withdrawal_credentials": "0x0062a90ebe71c4c01c4e057d7d13b944d9705f524ebfa24290c22477ab0517e4",
        "amount": "32000000000",
        "signature": "0xa87a4874d276982c471e981a113f8af74a31ffa7d18898a02df2419de2a7f02084065784aa2f743d9ddf80952986ea0b012190cd866f1f2d9c633a7a33c2725d0b181906d413c82e2c18323154a2f7c7ae6f72686782ed9e423070daa00db05b"
      },
      "block_number": 3086571,
      "index": 0,
      "signature_is_valid": false
    },
    {
      "deposit_data": {
        "pubkey": "0xb1d0ec8f907e023ea7b8cb1236be8a74d02ba3f13aba162da4a68e9ffa2e395134658d150ef884bcfaeecdf35c286496",
        "withdrawal_credentials": "0x00a6aa2a632a6c4847cf87ef96d789058eb65bfaa4cc4e0ebc39237421c22e54",
        "amount": "32000000000",
        "signature": "0x8d0f8ec11935010202d6dde9ab437f8d835b9cfd5052c001be5af9304f650ada90c5363022e1f9ef2392dd222cfe55b40dfd52578468d2b2092588d4ad3745775ea4d8199216f3f90e57c9435c501946c030f7bfc8dbd715a55effa6674fd5a4"
      },
      "block_number": 3086579,
      "index": 1,
      "signature_is_valid": false
    }
  ]
}
```

### `/lighthouse/beacon/states/{state_id}/ssz`

Obtains a `BeaconState` in SSZ bytes. Useful for obtaining a genesis state.

The `state_id` parameter is identical to that used in the [Standard Eth2.0 API
`beacon/state`
routes](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateRoot).

```bash
curl -X GET "http://localhost:5052/lighthouse/beacon/states/0/ssz" | jq
```

*Example omitted for brevity, the body simply contains SSZ bytes.*
