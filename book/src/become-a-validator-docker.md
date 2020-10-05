# Become a Validator: Using Docker

Sigma Prime maintains the
[sigp/lighthouse-docker](https://github.com/sigp/lighthouse-docker) repository
which provides an easy way to run Lighthouse without building the Lighthouse
binary yourself.

> Note: when you're running the Docker Hub image you're relying upon a
> pre-built binary instead of building from source. If you want the highest
> assurance you're running the _real_ Lighthouse,
> [build the docker image yourself](./docker.md) instead. You'll need some
> experience with docker-compose to integrate your locally built docker image
> with the docker-compose environment.

## 0. Install Docker Compose

 Docker Compose relies on Docker Engine for any meaningful work, so make sure you have Docker Engine installed either locally or remote, depending on your setup.

- On desktop systems like [Docker Desktop for Mac](https://docs.docker.com/docker-for-mac/install/) and [Docker Desktop for Windows](https://docs.docker.com/docker-for-windows/install/), Docker Compose is included as part of those desktop installs, so the desktop install is all you need.

- On Linux systems, you'll need to first [install the Docker for your OS](https://docs.docker.com/install/#server) and then [follow the instuctions here](https://docs.docker.com/compose/install/#install-compose-on-linux-systems).

> For more on installing Compose, see [here](https://docs.docker.com/compose/install/).


## 1. Clone the repository

Once you have Docker Compose installed, clone the
[sigp/lighthouse-docker](https://github.com/sigp/lighthouse-docker) repository:

```bash
 git clone https://github.com/sigp/lighthouse-docker
 cd lighthouse-docker
```

## 2. Configure the Docker environment

Then, create a file named `.env` with the following contents (these values are
documented
[here](https://github.com/sigp/lighthouse-docker/blob/master/default.env)):

```bash
DEBUG_LEVEL=info
START_GETH=true
START_VALIDATOR=true
VALIDATOR_COUNT=1
VOTING_ETH1_NODE=http://geth:8545
```

> To specify a non-default testnet add `TESTNET=<testnet>` to the above file. <testnet> can be `altona` or `medalla`.

_This `.env` file should live in the `lighthouse-docker` directory alongside the
`docker-compose.yml` file_.

## 3. Start Lighthouse

Start the docker-compose environment (you may need to prefix the below command with `sudo`):

```bash
 docker-compose up
```

Watch the output of this command for the `Decrypted validator keystore pubkey`
log, as it contains your `voting_pubkey` -- the primary identifier for your new
validator. This key is useful for finding your validator in block explorers.
Here's an example of the log:

```bash
validator_client_1  | Jun 01 00:29:24.418 INFO Decrypted validator keystore      voting_pubkey: 0x9986ade7a974d2fe2d0fc84a8c04153873337d533d43a83439cab8ec276410686dd69aa808605a7324f34e52497a3f41
```
This is one of the earlier logs outputted, so you may have to scroll up or perform a search in your terminal to find it.

> Note: `docker-compose up` generates  a new  sub-directory -- to store your validator's deposit data, along with its voting and withdrawal keys -- in the `lighthouse-data/validators` directory. This sub-directory is identified by your validator's `voting_pubkey` (the same `voting_pubkey` you see in the logs). So this is another way you can find it.

> Note: the docker-compose setup includes a fast-synced geth node. So you can
> expect the `beacon_node` to log some eth1-related errors whilst the geth node
> boots and becomes synced. This will only happen on the first start of the
> compose environment or if geth loses sync.

> Note: If you are participating in the genesis of a network (the network has
> not launched yet) you will notice errors in the validator client. This is
> because the beacon node not expose its HTTP API until
> the genesis of the network is known (approx 2 days before the network
> launches).

> Note: Docker exposes ports TCP 9000 and UDP 9000 by default. Although not
> strictly required, we recommend setting up port forwards to expose these
> ports publicly. For more information see the FAQ or the [Advanced Networking](advanced_networking.html)
> section

To find an estimate for how long your beacon node will take to finish syncing, look for logs that look like this:

```bash
beacon_node_1       | Mar 16 11:33:53.979 INFO Syncing
est_time: 47 mins, speed: 16.67 slots/sec, distance: 47296 slots (7 days 14 hrs), peers: 3, service: slot_notifier
```

You'll find the estimated time under `est_time`. In the example above, that's `47 mins`.

If your beacon node hasn't finished syncing yet, you'll see some ERRO messages indicating that your node hasn't synced yet:

```bash
validator_client_1  | Mar 16 11:34:36.086 ERRO Beacon node is not synced               current_epoch: 6999, node_head_epoch: 5531, service: duties
```

It's safest to wait for your node to sync before moving on to the next step, otherwise your validator may activate before you're able to produce blocks and attestations (and you may be penalized as a result).

However, since it generally takes somewhere between [4 and 8 hours](./faq.md) after depositing for a validator to become active, if your `est_time` is less than 4 hours, you _should_ be fine to just move on to the next step. After all, this is a testnet and you're only risking Goerli ETH!

## Installation complete!

In the [next step](become-a-validator.html#2-submit-your-deposit-to-goerli) you'll need to upload your validator's deposit data. This data is stored in a file called `eth1_deposit_data.rlp`.

You'll find it in `lighthouse-docker/.lighthouse/validators/` -- in the sub-directory that corresponds to your validator's public key (`voting_pubkey`).


> For example, if you ran [step 1](become-a-validator-docker.html#1-clone-the-repository) in `/home/karlm/`, and your validator's `voting_pubkey` is `0x8592c7..`, then you'll find your `eth1_deposit_data.rlp` file in the following directory:
>
>`/home/karlm/lighthouse-docker/.lighthouse/validators/0x8592c7../`

Once you've located `eth1_deposit_data.rlp`, you're ready to move on to [Become a Validator: Step 2](become-a-validator.html#2-submit-your-deposit-to-goerli).
