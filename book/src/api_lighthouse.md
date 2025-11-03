# Lighthouse Non-Standard APIs

Lighthouse fully supports the standardization efforts at
[github.com/ethereum/beacon-APIs](https://github.com/ethereum/beacon-APIs).
However, sometimes development requires additional endpoints that shouldn't
necessarily be defined as a broad-reaching standard.  Such endpoints are placed
behind the `/lighthouse` path.

The endpoints behind the `/lighthouse` path are:

- Not intended to be stable.
- Not guaranteed to be safe.
- For testing and debugging purposes only.

Although we don't recommend that users rely on these endpoints, we
document them briefly so they can be utilized by developers and
researchers.

## `/lighthouse/health`

*Note: This endpoint is presently only available on Linux.*

Returns information regarding the health of the host machine.

```bash
curl -X GET "http://localhost:5052/lighthouse/health" -H  "accept: application/json" | jq
```

```json
{
  "data": {
    "sys_virt_mem_total": 16671133696,
    "sys_virt_mem_available": 8273715200,
    "sys_virt_mem_used": 7304818688,
    "sys_virt_mem_free": 2998190080,
    "sys_virt_mem_percent": 50.37101,
    "sys_virt_mem_cached": 5013975040,
    "sys_virt_mem_buffers": 1354149888,
    "sys_loadavg_1": 2.29,
    "sys_loadavg_5": 3.48,
    "sys_loadavg_15": 3.72,
    "cpu_cores": 4,
    "cpu_threads": 8,
    "system_seconds_total": 5728,
    "user_seconds_total": 33680,
    "iowait_seconds_total": 873,
    "idle_seconds_total": 177530,
    "cpu_time_total": 217447,
    "disk_node_bytes_total": 358443397120,
    "disk_node_bytes_free": 70025089024,
    "disk_node_reads_total": 1141863,
    "disk_node_writes_total": 1377993,
    "network_node_bytes_total_received": 2405639308,
    "network_node_bytes_total_transmit": 328304685,
    "misc_node_boot_ts_seconds": 1620629638,
    "misc_os": "linux",
    "pid": 4698,
    "pid_num_threads": 25,
    "pid_mem_resident_set_size": 783757312,
    "pid_mem_virtual_memory_size": 2564665344,
    "pid_process_seconds_total": 22
  }
}

```

## `/lighthouse/ui/health`

Returns information regarding the health of the host machine.

```bash
curl -X GET "http://localhost:5052/lighthouse/ui/health" -H  "accept: application/json" | jq
```

```json
{
  "data": {
    "total_memory": 16443219968,
    "free_memory": 1283739648,
    "used_memory": 5586264064,
    "sys_loadavg_1": 0.59,
    "sys_loadavg_5": 1.13,
    "sys_loadavg_15": 2.41,
    "cpu_cores": 4,
    "cpu_threads": 8,
    "global_cpu_frequency": 3.4,
    "disk_bytes_total": 502390845440,
    "disk_bytes_free": 9981386752,
    "system_uptime": 660706,
    "app_uptime": 105,
    "system_name": "Arch Linux",
    "kernel_version": "5.19.13-arch1-1",
    "os_version": "Linux rolling Arch Linux",
    "host_name": "Computer1"
    "network_name": "wlp0s20f3",
    "network_bytes_total_received": 14105556611,
    "network_bytes_total_transmit": 3649489389,
    "nat_open": true,
    "connected_peers": 80,
    "sync_state": "Synced",
  }
}
```

## `/lighthouse/ui/validator_count`

Returns an overview of validators.

```bash
curl -X GET "http://localhost:5052/lighthouse/ui/validator_count" -H "accept: application/json" | jq
```

```json
{
  "data": {
    "active_ongoing":479508,
    "active_exiting":0,
    "active_slashed":0,
    "pending_initialized":28,
    "pending_queued":0,
    "withdrawal_possible":933,
    "withdrawal_done":0,
    "exited_unslashed":0,
    "exited_slashed":3
  }
}
```

## `/lighthouse/ui/validator_metrics`

Re-exposes certain metrics from the validator monitor to the HTTP API. This API requires that the beacon node to have the flag `--validator-monitor-auto`. This API will only return metrics for the validators currently being monitored and present in the POST data, or the validators running in the validator client.

```bash
curl -X POST "http://localhost:5052/lighthouse/ui/validator_metrics" -d '{"indices": [12345]}' -H "Content-Type: application/json" | jq
```

```json
{
  "data": {
    "validators": {
      "12345": {
        "attestation_hits": 10,
        "attestation_misses": 0,
        "attestation_hit_percentage": 100,
        "attestation_head_hits": 10,
        "attestation_head_misses": 0,
        "attestation_head_hit_percentage": 100,
        "attestation_target_hits": 5,
        "attestation_target_misses": 5,
        "attestation_target_hit_percentage": 50,
        "latest_attestation_inclusion_distance": 1
      }
    }
  }
}
```

Running this API without the flag `--validator-monitor-auto` in the beacon node will return null:

```json
{
  "data": {
    "validators": {}
  }
}
```

## `/lighthouse/syncing`

Returns the sync status of the beacon node.

```bash
curl -X GET "http://localhost:5052/lighthouse/syncing" -H  "accept: application/json" | jq
```

There are two possible outcomes, depending on whether the beacon node is syncing or synced.

1. Syncing:

   ```json
    {
      "data": {
        "SyncingFinalized": {
          "start_slot": "5478848",
          "target_slot": "5478944"
        }
      }
    }
   ```

1. Synced:

   ```json
   {
     "data": "Synced"
   }
   ```

## `/lighthouse/peers`

```bash
curl -X GET "http://localhost:5052/lighthouse/peers" -H  "accept: application/json" | jq
```

```json
[
  {
    "peer_id": "16Uiu2HAm2ZoWQ2zkzsMFvf5o7nXa7R5F7H1WzZn2w7biU3afhgov",
    "peer_info": {
      "score": {
        "Real": {
          "lighthouse_score": 0,
          "gossipsub_score": -18371.409037358582,
          "ignore_negative_gossipsub_score": false,
          "score": -21.816048231863316
        }
      },
      "client": {
        "kind": "Lighthouse",
        "version": "v4.1.0-693886b",
        "os_version": "x86_64-linux",
        "protocol_version": "eth2/1.0.0",
        "agent_string": "Lighthouse/v4.1.0-693886b/x86_64-linux"
      },
      "connection_status": {
        "status": "disconnected",
        "connections_in": 0,
        "connections_out": 0,
        "last_seen": 9028,
        "banned_ips": []
      },
      "listening_addresses": [
        "/ip4/212.102.59.173/tcp/23452",
        "/ip4/23.124.84.197/tcp/23452",
        "/ip4/127.0.0.1/tcp/23452",
        "/ip4/192.168.0.2/tcp/23452",
        "/ip4/192.168.122.1/tcp/23452"
      ],
      "seen_addresses": [
        "23.124.84.197:23452"
      ],
      "sync_status": {
        "Synced": {
          "info": {
            "head_slot": "5468141",
            "head_root": "0x7acc017a199c0cf0693a19e0ed3a445a02165c03ea6f46cb5ffb8f60bf0ebf35",
            "finalized_epoch": "170877",
            "finalized_root": "0xbbc3541637976bd03b526de73e60a064e452a4b873b65f43fa91fefbba140410"
          }
        }
      },
      "meta_data": {
        "V2": {
          "seq_number": 501,
          "attnets": "0x0000020000000000",
          "syncnets": "0x00"
        }
      },
      "subnets": [],
      "is_trusted": false,
      "connection_direction": "Outgoing",
      "enr": "enr:-L64QI37ReMIki2Uqln3pcgQyAH8Y3ceSYrtJp1FlDEGSM37F7ngCpS9k-SKQ1bOHp0zFCkNxpvFlf_3o5OUkBRw0qyCAfqHYXR0bmV0c4gAAAIAAAAAAIRldGgykGKJQe8DABAg__________-CaWSCdjSCaXCEF3xUxYlzZWNwMjU2azGhAmoW921eIvf8pJhOvOwuxLSxKnpLY2inE_bUILdlZvhdiHN5bmNuZXRzAIN0Y3CCW5yDdWRwgluc"
    }
  }
]
```

## `/lighthouse/peers/connected`

Returns information about connected peers.

```bash
curl -X GET "http://localhost:5052/lighthouse/peers/connected" -H  "accept: application/json" | jq
```

```json
[
 {
    "peer_id": "16Uiu2HAmCAvpoYE6ABGdQJaW4iufVqNCTJU5AqzyZPB2D9qba7ZU",
    "peer_info": {
      "score": {
        "Real": {
          "lighthouse_score": 0,
          "gossipsub_score": 0,
          "ignore_negative_gossipsub_score": false,
          "score": 0
        }
      },
      "client": {
        "kind": "Lighthouse",
        "version": "v3.5.1-319cc61",
        "os_version": "x86_64-linux",
        "protocol_version": "eth2/1.0.0",
        "agent_string": "Lighthouse/v3.5.1-319cc61/x86_64-linux"
      },
      "connection_status": {
        "status": "connected",
        "connections_in": 0,
        "connections_out": 1,
        "last_seen": 0
      },
      "listening_addresses": [
        "/ip4/144.91.92.17/tcp/9000",
        "/ip4/127.0.0.1/tcp/9000",
        "/ip4/172.19.0.3/tcp/9000"
      ],
      "seen_addresses": [
        "144.91.92.17:9000"
      ],
      "sync_status": {
        "Synced": {
          "info": {
            "head_slot": "5468930",
            "head_root": "0x25409073c65d2f6f5cee20ac2eff5ab980b576ca7053111456063f8ff8f67474",
            "finalized_epoch": "170902",
            "finalized_root": "0xab59473289e2f708341d8e5aafd544dd88e09d56015c90550ea8d16c50b4436f"
          }
        }
      },
      "meta_data": {
        "V2": {
          "seq_number": 67,
          "attnets": "0x0000000080000000",
          "syncnets": "0x00"
        }
      },
      "subnets": [
        {
          "Attestation": "39"
        }
      ],
      "is_trusted": false,
      "connection_direction": "Outgoing",
      "enr": "enr:-Ly4QHd3RHJdkuR1iE6MtVtibC5S-aiWGPbwi4cG3wFGbqxRAkAgLDseTzPFQQIehQ7LmO7KIAZ5R1fotjMQ_LjA8n1Dh2F0dG5ldHOIAAAAAAAQAACEZXRoMpBiiUHvAwAQIP__________gmlkgnY0gmlwhJBbXBGJc2VjcDI1NmsxoQL4z8A7B-NS29zOgvkTX1YafKandwOtrqQ1XRnUJj3se4hzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA"
    }
  }
]
```

## `/lighthouse/proto_array`

```bash
curl -X GET "http://localhost:5052/lighthouse/proto_array" -H  "accept: application/json" | jq
```

*Example omitted for brevity.*

## `/lighthouse/validator_inclusion/{epoch}/{validator_id}`

See [Validator Inclusion APIs](./api_validator_inclusion.md).

## `/lighthouse/validator_inclusion/{epoch}/global`

See [Validator Inclusion APIs](./api_validator_inclusion.md).

## `/lighthouse/liveness`

POST request that checks if any of the given validators have attested in the given epoch. Returns a list
of objects, each including the validator index, epoch, and `is_live` status of a requested validator.

This endpoint is used in doppelganger detection, and can only provide accurate information for the current, previous, or next epoch.

> Note that for this API, if you insert an arbitrary epoch other than the previous, current or next epoch of the network, it will return `"code:400"` and `BAD_REQUEST`.

```bash
curl -X POST "http://localhost:5052/lighthouse/liveness" -d '{"indices":["0","1"],"epoch":"1"}' -H  "content-type: application/json" | jq
```

```json
{
    "data": [
        {
            "index": "0",
            "epoch": "1",
            "is_live": true
        }
    ]
}
```

## `/lighthouse/database/info`

Information about the database's split point and anchor info.

```bash
curl "http://localhost:5052/lighthouse/database/info" | jq
```

```json
{
  "schema_version": 22,
  "config": {
    "block_cache_size": 5,
    "state_cache_size": 128,
    "compression_level": 1,
    "historic_state_cache_size": 1,
    "hdiff_buffer_cache_size": 16,
    "compact_on_init": false,
    "compact_on_prune": true,
    "prune_payloads": true,
    "hierarchy_config": {
      "exponents": [
        5,
        7,
        11
      ]
    },
    "prune_blobs": true,
    "epochs_per_blob_prune": 1,
    "blob_prune_margin_epochs": 0
  },
  "split": {
    "slot": "10530592",
    "state_root": "0xd27e6ce699637cf9b5c7ca632118b7ce12c2f5070bb25a27ac353ff2799d4466",
    "block_root": "0x71509a1cb374773d680cd77148c73ab3563526dacb0ab837bb0c87e686962eae"
  },
  "anchor": {
    "anchor_slot": "7451168",
    "oldest_block_slot": "3962593",
    "oldest_block_parent": "0x4a39f21367b3b9cc272744d1e38817bda5daf38d190dc23dc091f09fb54acd97",
    "state_upper_limit": "7454720",
    "state_lower_limit": "0"
  },
  "blob_info": {
    "oldest_blob_slot": "7413769",
    "blobs_db": true
  }
}
```

For more information about the split point, see the [Database Configuration](./advanced_database.md)
docs.

For archive nodes, the `anchor` will be:

```json
"anchor": {
    "anchor_slot": "0",
    "oldest_block_slot": "0",
    "oldest_block_parent": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "state_upper_limit": "0",
    "state_lower_limit": "0"
  },
```

indicating that all states with slots `>= 0` are available, i.e., full state history. For more information
on the specific meanings of these fields see the docs on [Checkpoint
Sync](./advanced_checkpoint_sync.md#how-to-run-an-archived-node).

## `/lighthouse/custody/backfill`

Starts a custody backfill sync from the next epoch with the node's latest custody requirements. The sync won't begin immediately, it waits until the next epoch is finalized before triggering.

This endpoint should only be used to fix nodes that may have partial custody columns due to a prior backfill bug (present in v8.0.0-rc.2). Use with caution as it re-downloads all historic custody data columns and may consume significant bandwidth.

```bash
curl -X POST "http://localhost:5052/lighthouse/custody/backfill"
```

## `/lighthouse/merge_readiness`

Returns the current difficulty and terminal total difficulty of the network. Before [The Merge](https://ethereum.org/en/roadmap/merge/) on 15<sup>th</sup> September 2022, you will see that the current difficulty is less than the terminal total difficulty, An example is shown below:

```bash
curl -X GET "http://localhost:5052/lighthouse/merge_readiness" | jq
```

```json
{
    "data":{
       "type":"ready",
       "config":{
          "terminal_total_difficulty":"6400"
       },
       "current_difficulty":"4800"
    }
 }
```

As all testnets and Mainnet have been merged, both values will be the same after The Merge. An example of response on the Goerli testnet:

```json
{
  "data": {
    "type": "ready",
    "config": {
      "terminal_total_difficulty": "10790000"
    },
    "current_difficulty": "10790000"
  }
}
```

## `/lighthouse/analysis/attestation_performance/{index}`

Fetch information about the attestation performance of a validator index or all validators for a
range of consecutive epochs.

Two query parameters are required:

- `start_epoch` (inclusive): the first epoch to compute attestation performance for.
- `end_epoch` (inclusive): the final epoch to compute attestation performance for.

Example:

```bash
curl -X GET "http://localhost:5052/lighthouse/analysis/attestation_performance/1?start_epoch=1&end_epoch=1" | jq
```

```json
[
  {
    "index": 1,
    "epochs": {
      "1": {
        "active": true,
        "head": true,
        "target": true,
        "source": true,
        "delay": 1
      }
    }
  }
]
```

Instead of specifying a validator index, you can specify the entire validator set by using `global`:

```bash
curl -X GET "http://localhost:5052/lighthouse/analysis/attestation_performance/global?start_epoch=1&end_epoch=1" | jq
```

```json
[
  {
    "index": 0,
    "epochs": {
      "1": {
        "active": true,
        "head": true,
        "target": true,
        "source": true,
        "delay": 1
      }
    }
  },
  {
    "index": 1,
    "epochs": {
      "1": {
        "active": true,
        "head": true,
        "target": true,
        "source": true,
        "delay": 1
      }
    }
  },
  {
    ..
  }
]

```

Caveats:

- For maximum efficiency the start_epoch should satisfy `(start_epoch * slots_per_epoch) % slots_per_restore_point == 1`.
  This is because the state *prior* to the `start_epoch` needs to be loaded from the database,
  and loading a state on a boundary is most efficient.

## `/lighthouse/analysis/block_rewards`

Fetch information about the block rewards paid to proposers for a range of consecutive blocks.

Two query parameters are required:

- `start_slot` (inclusive): the slot of the first block to compute rewards for.
- `end_slot` (inclusive): the slot of the last block to compute rewards for.

Example:

```bash
curl -X GET "http://localhost:5052/lighthouse/analysis/block_rewards?start_slot=1&end_slot=1" | jq
```

The first few lines of the response would look like:

```json
[
  {
    "total": 637260,
    "block_root": "0x4a089c5e390bb98e66b27358f157df825128ea953cee9d191229c0bcf423a4f6",
    "meta": {
      "slot": "1",
      "parent_slot": "0",
      "proposer_index": 93,
      "graffiti": "EF #vm-eth2-raw-iron-101"
    },
    "attestation_rewards": {
      "total": 637260,
      "prev_epoch_total": 0,
      "curr_epoch_total": 637260,
      "per_attestation_rewards": [
        {
          "50102": 780,
        }
      ]
    }
  }
]
```

Caveats:

- Presently only attestation and sync committee rewards are computed.
- The output format is verbose and subject to change. Please see [`BlockReward`][block_reward_src]
  in the source.
- For maximum efficiency the `start_slot` should satisfy `start_slot % slots_per_restore_point == 1`.
  This is because the state *prior* to the `start_slot` needs to be loaded from the database, and
  loading a state on a boundary is most efficient.

[block_reward_src]:
https://github.com/sigp/lighthouse/tree/unstable/common/eth2/src/lighthouse/block_rewards.rs

## `/lighthouse/analysis/block_packing`

Fetch information about the block packing efficiency of blocks for a range of consecutive
epochs.

Two query parameters are required:

- `start_epoch` (inclusive): the epoch of the first block to compute packing efficiency for.
- `end_epoch` (inclusive): the epoch of the last block to compute packing efficiency for.

```bash
curl -X GET "http://localhost:5052/lighthouse/analysis/block_packing_efficiency?start_epoch=1&end_epoch=1" | jq
```

An excerpt of the response looks like:

```json
[
  {
    "slot": "33",
    "block_hash": "0xb20970bb97c6c6de6b1e2b689d6381dd15b3d3518fbaee032229495f963bd5da",
    "proposer_info": {
      "validator_index": 855,
      "graffiti": "poapZoJ7zWNfK7F3nWjEausWVBvKa6gA"
    },
    "available_attestations": 3805,
    "included_attestations": 1143,
    "prior_skip_slots": 1
  },
  {
    ..
  }
]
```

Caveats:

- `start_epoch` must not be `0`.
- For maximum efficiency the `start_epoch` should satisfy `(start_epoch * slots_per_epoch) % slots_per_restore_point == 1`.
  This is because the state *prior* to the `start_epoch` needs to be loaded from the database, and
  loading a state on a boundary is most efficient.

## `/lighthouse/logs`

This is a Server Side Event subscription endpoint. This allows a user to read
the Lighthouse logs directly from the HTTP API endpoint. This currently
exposes INFO and higher level logs. It is only enabled when the `--gui` flag is set in the CLI.

Example:

```bash
curl -N "http://localhost:5052/lighthouse/logs"
```

Should provide an output that emits log events as they occur:

```json
{
"data": {
	  "time": "Mar 13 15:28:41",
	  "level": "INFO",
	  "msg": "Syncing",
	  "service": "slot_notifier",
	  "est_time": "1 hr 27 mins",
	  "speed": "5.33 slots/sec",
	  "distance": "28141 slots (3 days 21 hrs)",
	  "peers": "8"
	}
}
```

## `/lighthouse/nat`

Checks if the ports are open.

```bash
curl -X GET "http://localhost:5052/lighthouse/nat" | jq
```

An example of response:

```json
{
  "data": {
    "discv5_ipv4": true,
    "discv5_ipv6": false,
    "libp2p_ipv4": true,
    "libp2p_ipv6": false
  }
}
```
