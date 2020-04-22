# Lighthouse REST API: `/advanced`

The `/advanced` endpoints provide information Lighthouse specific data structures for advanced debugging.

## Endpoints

HTTP Path | Description |
| --- | -- |
[`/advanced/fork_choice`](#advancedfork_choice) | Get the `proto_array` fork choice object.
[`/advanced/operation_pool`](#advancedoperation_pool) | Get the Lighthouse `PersistedOperationPool` object.


## `/advanced/fork_choice`

Requests the `proto_array` fork choice object as represented in Lighthouse.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/advanced/fork_choice`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
{
    "prune_threshold": 256,
    "justified_epoch": 25,
    "finalized_epoch": 24,
    "nodes": [
        {
            "slot": 544,
            "root": "0x27103c56d4427cb4309dd202920ead6381d54d43277c29cf0572ddf0d528e6ea",
            "parent": null,
            "justified_epoch": 16,
            "finalized_epoch": 15,
            "weight": 256000000000,
            "best_child": 1,
            "best_descendant": 296
        },
        {
            "slot": 545,
            "root": "0x09af0e8d4e781ea4280c9c969d168839c564fab3a03942e7db0bfbede7d4c745",
            "parent": 0,
            "justified_epoch": 16,
            "finalized_epoch": 15,
            "weight": 256000000000,
            "best_child": 2,
            "best_descendant": 296
        },
    ],
    "indices": {
        "0xb935bb3651eeddcb2d2961bf307156850de982021087062033f02576d5df00a3": 59,
        "0x8f4ec47a34c6c1d69ede64d27165d195f7e2a97c711808ce51f1071a6e12d5b9": 189,
        "0xf675eba701ef77ee2803a130dda89c3c5673a604d2782c9e25ea2be300d7d2da": 173,
        "0x488a483c8d5083faaf5f9535c051b9f373ba60d5a16e77ddb1775f248245b281": 37
    }
}
```
_Truncated for brevity._

## `/advanced/operation_pool`

Requests the `PersistedOperationPool` object as represented in Lighthouse.

### HTTP Specification

| Property | Specification |
| --- |--- |
Path | `/advanced/operation_pool`
Method | GET
JSON Encoding | Object
Query Parameters | None
Typical Responses | 200

### Example Response

```json
{
    "attestations": [
        [
            {
                "v": [39, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 118, 215, 252, 51, 186, 76, 156, 157, 99, 91, 4, 137, 195, 209, 224, 26, 233, 233, 184, 38, 89, 215, 177, 247, 97, 243, 119, 229, 69, 50, 90, 24, 0, 0, 0, 0, 0, 0, 0, 79, 37, 38, 210, 96, 235, 121, 142, 129, 136, 206, 214, 179, 132, 22, 19, 222, 213, 203, 46, 112, 192, 26, 5, 254, 26, 103, 170, 158, 205, 72, 3, 25, 0, 0, 0, 0, 0, 0, 0, 164, 50, 214, 67, 98, 13, 50, 180, 108, 232, 248, 109, 128, 45, 177, 23, 221, 24, 218, 211, 8, 152, 172, 120, 24, 86, 198, 103, 68, 164, 67, 202, 1, 0, 0, 0, 0, 0, 0, 0]
            },
            [
                {
                    "aggregation_bits": "0x03",
                    "data": {
                        "slot": 807,
                        "index": 0,
                        "beacon_block_root": "0x7076d7fc33ba4c9c9d635b0489c3d1e01ae9e9b82659d7b1f761f377e545325a",
                        "source": {
                            "epoch": 24,
                            "root": "0x4f2526d260eb798e8188ced6b3841613ded5cb2e70c01a05fe1a67aa9ecd4803"
                        },
                        "target": {
                            "epoch": 25,
                            "root": "0xa432d643620d32b46ce8f86d802db117dd18dad30898ac781856c66744a443ca"
                        }
                    },
                    "signature": "0x8b1d624b0cd5a7a0e13944e90826878a230e3901db34ea87dbef5b145ade2fedbc830b6752a38a0937a1594211ab85b615d65f9eef0baccd270acca945786036695f4db969d9ff1693c505c0fe568b2fe9831ea78a74cbf7c945122231f04026"
                }
            ]
        ]
    ],
    "attester_slashings": [],
    "proposer_slashings": [],
    "voluntary_exits": []
}
```
_Truncated for brevity._
