# Run a Node

This section provides the detail for users who want to run a Lighthouse beacon node.
You should be finished with one [Installation](./installation.md) method of your choice to continue with the following steps:

1. Create a [JWT secret file](#step-1-create-a-jwt-secret-file)
1. Set up an [execution node](#step-2-set-up-an-execution-node);
1. Set up a [beacon node](#step-3-set-up-a-beacon-node-using-lighthouse);
1. [Check logs for sync status](#step-4-check-logs-for-sync-status);



## Step 1: Create a JWT secret file
A JWT secret file is used to secure the communication between the execution client and the consensus client. In this step, we will create a JWT secret file which will be used in later steps.

```bash
sudo mkdir -p /secrets
openssl rand -hex 32 | tr -d "\n" | sudo tee /secrets/jwt.hex
```

## Step 2: Set up an execution node

The Lighthouse beacon node *must* connect to an execution engine in order to validate the transactions present in blocks. The execution engine connection must be *exclusive*, i.e. you must have one execution node
per beacon node. The reason for this is that the beacon node _controls_ the execution node. Select an execution client from the list below and run it:


- [Nethermind](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/running-nethermind-post-merge)
- [Besu](https://besu.hyperledger.org/en/stable/public-networks/get-started/connect/mainnet/)
- [Erigon](https://github.com/ledgerwatch/erigon#beacon-chain-consensus-layer)
- [Geth](https://geth.ethereum.org/docs/getting-started/consensus-clients)


> Note: Each execution engine has its own flags for configuring the engine API and JWT secret to connect to a beacon node. Please consult the relevant page of your execution engine as above for the required flags.


Once the execution client is up, just let it continue running. The execution client will start syncing when it connects to a beacon node. Depending on the execution client and computer hardware specifications, syncing can take from a few hours to a few days. You can safely proceed to Step 3 to set up a beacon node while the execution client is still syncing.

## Step 3: Set up a beacon node using Lighthouse

In this step, we will set up a beacon node. Use the following command to start a beacon node that connects to the execution node:

### Staking

```
lighthouse bn \
  --network mainnet \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --http
```

> Note: If you download the binary file, you need to navigate to the directory of the binary file to run the above command. 

Notable flags: 
- `--network` flag, which selects a network:
  - `lighthouse` (no flag): Mainnet.
  - `lighthouse --network mainnet`: Mainnet.
  - `lighthouse --network goerli`: Goerli (testnet).
  - `lighthouse --network sepolia`: Sepolia (testnet).
  - `lighthouse --network chiado`: Chiado (testnet).
  - `lighthouse --network gnosis`: Gnosis chain.

    > Note:  Using the correct `--network` flag is very important; using the wrong flag can
result in penalties, slashings or lost deposits. As a rule of thumb, *always*
provide a `--network` flag instead of relying on the default.
- `--execution-endpoint`: the URL of the execution engine API. If the execution engine is running on the same computer with the default port, this will be
  `http://localhost:8551`.
- `--execution-jwt`: the path to the JWT secret file shared by Lighthouse and the
  execution engine. This is a mandatory form of authentication which ensures that Lighthouse has the authority to control the execution engine.
- `--checkpoint-sync-url`: Lighthouse supports fast sync from a recent finalized checkpoint. Checkpoint sync is *optional*; however, we **highly recommend** it since it is substantially faster than syncing from genesis while still providing the same functionality. The checkpoint sync is done using [public endpoints](https://eth-clients.github.io/checkpoint-sync-endpoints/) provided by the Ethereum community. For example, in the above command, we use the URL for Sigma Prime's checkpoint sync server for mainnet `https://mainnet.checkpoint.sigp.io`.
- `--http`: to expose an HTTP server of the beacon chain. The default listening address is `http://localhost:5052`. The HTTP API is required for the beacon node to accept connections from the *validator client*, which manages keys.



If you intend to run the beacon node without running the validator client (e.g., for non-staking purposes such as supporting the network), you can modify the above command so that the beacon node is configured for non-staking purposes:


### Non-staking

``` 
lighthouse bn \
  --network mainnet \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex \
  --checkpoint-sync-url https://mainnet.checkpoint.sigp.io \
  --disable-deposit-contract-sync
```

Since we are not staking, we can use the `--disable-deposit-contract-sync` flag to disable syncing of deposit logs from the execution node.



Once Lighthouse runs, we can monitor the logs to see if it is syncing correctly.



## Step 4: Check logs for sync status
Several logs help you identify if Lighthouse is running correctly. 

### Logs - Checkpoint sync
If you run Lighthouse with the flag `--checkpoint-sync-url`, Lighthouse will print a message to indicate that checkpoint sync is being used:

```
INFO Starting checkpoint sync                remote_url: http://remote-bn:8000/, service: beacon
```

After a short time (usually less than a minute), it will log the details of the checkpoint
loaded from the remote beacon node:

```
INFO Loaded checkpoint block and state       state_root: 0xe8252c68784a8d5cc7e5429b0e95747032dd1dcee0d1dc9bdaf6380bf90bc8a6, block_root: 0x5508a20147299b1a7fe9dbea1a8b3bf979f74c52e7242039bd77cbff62c0695a, slot: 2034720, service: beacon
```

Once the checkpoint is loaded, Lighthouse will sync forwards to the head of the chain.

If a validator client is connected to the beacon node it will be able to start its duties as soon as forwards sync completes, which typically takes 1-2 minutes.

> Note: If you have an existing Lighthouse database, you will need to delete the database by using the `--purge-db` flag or manually delete the database with `sudo rm -r /path_to_database/beacon`. If you do use a `--purge-db` flag, once checkpoint sync is complete, you can remove the flag upon a restart.

> **Security Note**: You should cross-reference the `block_root` and `slot` of the loaded checkpoint
> against a trusted source like another [public endpoint](https://eth-clients.github.io/checkpoint-sync-endpoints/),
> a friend's node, or a block explorer.

### Backfilling Blocks

Once forwards sync completes, Lighthouse will commence a "backfill sync" to download the blocks
from the checkpoint back to genesis.

The beacon node will log messages similar to the following each minute while it completes backfill
sync:

```
INFO Downloading historical blocks  est_time: 5 hrs 0 mins, speed: 111.96 slots/sec, distance: 2020451 slots (40 weeks 0 days), service: slot_notifier
```

Once backfill is complete, a `INFO Historical block download complete` log will be emitted.

Check out the [FAQ](./checkpoint-sync.md#faq) for more information on checkpoint sync.

### Logs - Syncing

You should see that Lighthouse remains in sync and marks blocks
as `verified` indicating that they have been processed successfully by the execution engine:

```
INFO Synced, slot: 3690668, block: 0x1244…cb92, epoch: 115333, finalized_epoch: 115331, finalized_root: 0x0764…2a3d, exec_hash: 0x929c…1ff6 (verified), peers: 78
```

Once you see the above message - congratulations! This means that your node is synced and you have contributed to the decentralization and security of the Ethereum network. 

## Further readings

Several other resources are the next logical step to explore after running your beacon node: 

- If you intend to run a validator, proceed to [become a validator](./mainnet-validator.md);
- Explore how to [manage your keys](./key-management.md);
- Research on [validator management](./validator-management.md);
- Dig into the [APIs](./api.md) that the beacon node and validator client provide;
- Study even more about [checkpoint sync](./checkpoint-sync.md); or
- Investigate what steps had to be taken in the past to execute a smooth [merge migration](./merge-migration.md).

Finally, if you are struggling with anything, join our [Discord](https://discord.gg/cyAszAh). We are happy to help!
