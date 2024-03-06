# Blobs

In the Deneb network upgrade, one of the changes is the implementation of EIP-4844, also known as [Proto-danksharding](https://blog.ethereum.org/2024/02/27/dencun-mainnet-announcement). Alongside with this, a new term named `blob` (binary large object) is introduced. Blobs are "side-cars" carrying transactions data in a block. They are mainly used by Ethereum layer 2 operators. As far as stakers are concerned, the main difference with the introduction of blobs is the increased storage requirement. 

### FAQ

1. What is the storage requirement for blobs?

   We expect an additional increase of ~50 GB of storage requirement for blobs (on top of what is required by the consensus and execution clients database). The calculation is as below:

   One blob is 128 KB in size. Each block can carry a maximum of 6 blobs. Blobs will be kept for 4096 epochs and pruned afterwards. This means that the maximum increase in storage requirement will be:

   ```
   128 KB / blob * 6 blobs / block * 32 blocks / epoch * 4096 epochs = 96 GB
   ```

   However, in practice, it is expected that not all blocks will be full of blobs. A practical scenario is that each block contains 3 blobs on average, which translates to an increase of storage requirement of 48 GB.


1. Do I have to add any flags for blobs?

   No, you can use the default values for blobs-related flags, which means you do not need add or remove any flags. 

1. What if I want to keep all blobs?

   Use the flag `--prune-blobs false` in the beacon node. Please note that this will keep all blobs and will thus require a high storage space. 
   
   To keep blobs for a custom period, you may use the flag `--blob-prune-margin-epochs <EPOCHS>` which keeps blobs for 4096+EPOCHS specified in the flag.

1. How to see the info of blobs database?

   We can call the API: 

   ```bash
   curl "http://localhost:5052/lighthouse/database/info" | jq
   ```

   Refer to [Lighthouse API](./api-lighthouse.md#lighthousedatabaseinfo) for an example of response. 