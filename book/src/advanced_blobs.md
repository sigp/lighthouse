# Data columns

With the [Fusaka](https://ethereum.org/roadmap/fusaka) upgrade, the main feature [PeerDAS](https://ethereum.org/roadmap/fusaka#peerdas) allows storing only a portion of blob data, known as data columns, thus reducing the storage and bandwidth requirements of a full node. This however also means that a full node will not be able to serve blobs after Fusaka. To continue serving blobs, run the beacon node with `--semi-supernode` or `--supernode`. Note that this comes at a significant increase in storage and bandwidth requirements, see [this blog post about PeerDAS](https://blog.sigmaprime.io/peerdas-distributed-blob-building.html) and [Fusaka bandwidth estimation](https://ethpandaops.io/posts/fusaka-bandwidth-estimation/) for more details.

> Note: the above assumes that the beacon node has no attached validators. If the beacon node has attached validators, then it is required to custody (store) a certain number of data columns which increases with the number of staked ETH. For example, if the staked ETH is `$\geq$` 2048 ETH, then due to custody requirement, it will make the beacon node a semi-supernode ; if `$\geq$` 4096 ETH, the beacon node will be a supernode without needing the flag.

Table below summarizes the role of relevant flags in Lighthouse beacon node:

|                     | Post-Deneb, Pre-Fulu                      |                                                              | Post-Fulu                                        |                                                          |
|---------------------|-------------------------------------------|--------------------------------------------------------------|--------------------------------------------------|----------------------------------------------------------|
| Flag                | Usage                                     | Can serve blobs?                                             | Usage                                            | Can serve blobs?                                         |
| --prune-blobs false | Does not prune blobs since using the flag | Yes, for blobs since using the flag and for the past 18 days | Does not prune data columns since using the flag | No                                                       |
| --semi-supernode    | -                                         | -                                                            | Store half data columns                          | Yes, for blobs since using the flag for a max of 18 days |
| --supernode         | -                                         | -                                                            | Store all data columns                           | Yes, for blobs since using the flag for a max of 18 days |

While both `--supernode` and `--semi-supernode` can serve blobs, a supernode will be faster to respond to blobs queries as it skips the blob reconstruction step. Running a supernode also helps the network by serving the data columns to its peers.

Combining `--prune-blobs false` and `--supernode` (or `--semi-supernode`) implies that no data columns will be pruned, and the node will be able to serve blobs since using the flag.

If you want historical blob data beyond the data availability period (18 days), you can backfill blobs or data columns with the experimental flag `--complete-blobs-backfill`. However, do note that this is an experimental feature and it may cause some issues, e.g., the node may block most of its peers.

**⚠️ The following section on Blobs is archived and not maintained as blobs are stored in the form of data columns after the Fulu fork ⚠️**

## Blobs

In the Deneb network upgrade, one of the changes is the implementation of EIP-4844, also known as [Proto-danksharding](https://blog.ethereum.org/2024/02/27/dencun-mainnet-announcement). Alongside with this, a new term named `blob` (binary large object) is introduced. Blobs are "side-cars" carrying transaction data in a block. They are mainly used by Ethereum layer 2 operators. As far as stakers are concerned, the main difference with the introduction of blobs is the increased storage requirement.

## FAQ

1. What is the storage requirement for blobs?

   After Deneb, we expect an additional increase of ~50 GB of storage requirement for blobs (on top of what is required by the consensus and execution clients database). The calculation is as below:

   One blob is 128 KB in size. Each block can carry a maximum of 6 blobs. Blobs will be kept for 4096 epochs and pruned afterwards. This means that the maximum increase in storage requirement will be:

   ```text
   2**17 bytes / blob * 6 blobs / block * 32 blocks / epoch * 4096 epochs = 96 GB
   ```

   However, the blob base fee targets 3 blobs per block and it works similarly to how EIP-1559 operates in the Ethereum gas fee. Therefore, practically it is very likely to average to 3 blobs per blocks, which translates to a storage requirement of 48 GB.

   After Electra, the target blobs is increased to 6 blobs per block. This means blobs storage is expected to use ~100GB of disk space.

1. Do I have to add any flags for blobs?

   No, you can use the default values for blob-related flags, which means you do not need add or remove any flags.

1. What if I want to keep all blobs?

   Use the flag `--prune-blobs false` in the beacon node. The storage requirement will be:

   ```text
   2**17 bytes * 6 blobs / block * 7200 blocks / day * 30 days = 158GB / month or 1896GB / year
   ```

   To keep blobs for a custom period, you may use the flag `--blob-prune-margin-epochs <EPOCHS>` which keeps blobs for 4096+EPOCHS specified in the flag.

1. How to see the info of the blobs database?

   We can call the API:

   ```bash
   curl "http://localhost:5052/lighthouse/database/info" | jq
   ```

   Refer to [Lighthouse API](./api_lighthouse.md#lighthousedatabaseinfo) for an example response.
