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

*Available on Linux and macOS.*

```bash
curl -X GET "http://localhost:5052/lighthouse/system" -H  "accept: application/json" | jq
```

```json
{
    "data": {
        "health": {
            "pid": 11612,
            "pid_mem_resident_set_size": 170893312,
            "pid_mem_virtual_memory_size": 1401901056,
            "sys_virt_mem_total": 8363692032,
            "sys_virt_mem_available": 5679951872,
            "sys_virt_mem_used": 2435825664,
            "sys_virt_mem_free": 2547994624,
            "sys_virt_mem_percent": 32.087982,
            "sys_loadavg_1": 0.24,
            "sys_loadavg_5": 0.55,
            "sys_loadavg_15": 1.42,
            "network": {
                "rx_bytes": 1333660554356,
                "rx_errors": 824206201966,
                "rx_packets": 2565207513,
                "tx_bytes": 3048133285,
                "tx_errors": 0,
                "tx_packets": 0
            }
        },
        "drives": [
            {
                "filesystem": "udev",
                "avail": 4168499200,
                "used": 0,
                "used_pct": 0,
                "total": 4168499200,
                "mounted_on": "/dev"
            },
            {
                "filesystem": "/dev/vda1",
                "avail": 91556573184,
                "used": 74761998336,
                "used_pct": 44,
                "total": 166318571520,
                "mounted_on": "/"
            },
            {
                "filesystem": "/dev/vda15",
                "avail": 105666560,
                "used": 3756032,
                "used_pct": 3,
                "total": 109422592,
                "mounted_on": "/boot/efi"
            }
        ]
    }
}
```

### `/lighthouse/system/health`

```bash
curl -X GET "http://localhost:5052/lighthouse/health" -H  "accept: application/json" | jq
```

```json
{
    "data": {
        "pid": 11612,
        "pid_mem_resident_set_size": 396988416,
        "pid_mem_virtual_memory_size": 1902653440,
        "sys_virt_mem_total": 8363692032,
        "sys_virt_mem_available": 5458038784,
        "sys_virt_mem_used": 2656464896,
        "sys_virt_mem_free": 2229014528,
        "sys_virt_mem_percent": 34.741276,
        "sys_loadavg_1": 2.54,
        "sys_loadavg_5": 1.61,
        "sys_loadavg_15": 1.64,
        "network": {
            "rx_bytes": 1333721410240,
            "rx_errors": 824208688988,
            "rx_packets": 2565265020,
            "tx_bytes": 3048160193,
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
{
    "data": [
        {
            "filesystem": "udev",
            "avail": 4168499200,
            "used": 0,
            "used_pct": 0,
            "total": 4168499200,
            "mounted_on": "/dev"
        },
        {
            "filesystem": "/dev/vda1",
            "avail": 91473604608,
            "used": 74844966912,
            "used_pct": 45,
            "total": 166318571520,
            "mounted_on": "/"
        },
        {
            "filesystem": "/dev/vda15",
            "avail": 105666560,
            "used": 3756032,
            "used_pct": 3,
            "total": 109422592,
            "mounted_on": "/boot/efi"
        }
    ]
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

### `/lighthouse/beacon/states/{state_id}/ssz`

Obtains a `BeaconState` in SSZ bytes. Useful for obtaining a genesis state.

The `state_id` parameter is identical to that used in the [Standard Eth2.0 API
`beacon/state`
routes](https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateRoot).

```bash
curl -X GET "http://localhost:5052/lighthouse/beacon/states/0/ssz" | jq
```

*Example omitted for brevity, the body simply contains SSZ bytes.*
