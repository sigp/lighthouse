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

### `/lighthouse/system`

```bash
curl -X GET "http://localhost:5052/lighthouse/system" -H  "accept: application/json" | jq
```

```json

```

### `/lighthouse/system/health`

```bash
curl -X GET "http://localhost:5052/lighthouse/health" -H  "accept: application/json" | jq
```

```json
{
    "data": {
        "pid": 92063,
        "pid_mem_resident_set_size": 188657664,
        "pid_mem_virtual_memory_size": 4852129792,
        "sys_virt_mem_total": 17179869184,
        "sys_virt_mem_available": 6760796160,
        "sys_virt_mem_used": 8087846912,
        "sys_virt_mem_free": 1614999552,
        "sys_virt_mem_percent": 60.646988,
        "sys_loadavg_1": 4.01708984375,
        "sys_loadavg_5": 3.17626953125,
        "sys_loadavg_15": 3.8837890625,
        "network": {
            "rx_bytes": 193094299648,
            "rx_errors": 66251016192,
            "rx_packets": 106043274,
            "tx_bytes": 47319518,
            "tx_errors": 0,
            "tx_packets": 0
        }
    }
}
```

### `/lighthouse/system/drives`

```bash
curl -X GET "http://localhost:5052/lighthouse/drives" -H  "accept: application/json" | jq
```

```json

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
