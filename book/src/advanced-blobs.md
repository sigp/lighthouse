# Blobs

In the Deneb network upgrade, one of the changes is the implementation of EIP-4844, also known as [Proto-danksharding](https://blog.ethereum.org/2024/02/27/dencun-mainnet-announcement). Alongside with this, a new term named `blob` (binary large object) is introduced. Blobs are "side-cars" carrying transaction data in a block. They are mainly used by Ethereum layer 2 operators. As far as stakers are concerned, the main difference with the introduction of blobs is the increased storage requirement.

## FAQ

1. What is the storage requirement for blobs?

   We expect an additional increase of ~50 GB of storage requirement for blobs (on top of what is required by the consensus and execution clients database). The calculation is as below:

   One blob is 128 KB in size. Each block can carry a maximum of 6 blobs. Blobs will be kept for 4096 epochs and pruned afterwards. This means that the maximum increase in storage requirement will be:

   ```text
   2**17 bytes / blob * 6 blobs / block * 32 blocks / epoch * 4096 epochs = 96 GB
   ```

   However, the blob base fee targets 3 blobs per block and it works similarly to how EIP-1559 operates in the Ethereum gas fee. Therefore, practically it is very likely to average to 3 blobs per blocks, which translates to a storage requirement of 48 GB.

1. Do I have to add any flags for blobs?

   No, you can use the default values for blob-related flags, which means you do not need add or remove any flags.

1. What if I want to keep all blobs?

   Use the flag `--prune-blobs false` in the beacon node. The storage requirement will be:

   ```text
   2**17 bytes * 3 blobs / block * 7200 blocks / day * 30 days = 79GB / month or 948GB / year
   ```

   To keep blobs for a custom period, you may use the flag `--blob-prune-margin-epochs <EPOCHS>` which keeps blobs for 4096+EPOCHS specified in the flag.

1. How to see the info of the blobs database?

   We can call the API:

   ```bash
   curl "http://localhost:5052/lighthouse/database/info" | jq
   ```

   Refer to [Lighthouse API](./api-lighthouse.md#lighthousedatabaseinfo) for an example response.
