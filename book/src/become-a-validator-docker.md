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

### 1. Clone the repository

Once you have docker-compose
[installed](https://docs.docker.com/compose/install/), clone the
[sigp/lighthouse-docker](https://github.com/sigp/lighthouse-docker) repository.

```bash
$ git clone https://github.com/sigp/lighthouse-docker
$ cd lighthouse-docker
```

### 2. Configure the docker environment

Then, create a file named `.env` with the following contents (these values are
documented
[here](https://github.com/sigp/lighthouse-docker/blob/master/default.env)):

```bash
DEBUG_LEVEL=info
START_GETH=true
START_VALIDATOR=true
VALIDATOR_COUNT=1
VOTING_ETH1_NODE=http://geth:8545
DEPOSIT_VALUE=3200000000
```

_This `.env` file should live in the `lighthouse-docker` directory alongside the
`docker-compose.yml` file_.

### 3. Start Lighthouse

Start the docker-compose environment (you may need to use `sudo`):

```bash
$ docker-compose up
```

Watch the output of this command for the `Saved new validator to disk` log, as
the `voting_pubkey` is the primary identifier for your new validator. This is
useful for finding your validator in block explorers. Here's an example of the
log:

```bash
validator_client_1  |  Jan 10 12:06:05.632 INFO Saved new validator to disk             voting_pubkey: 0x8fc28504448783b10b0a7f5a321505b07ad2ad8d6a8430b8868a0fcdedee43766bee725855506626085776e020dfa472
```

> Note: the docker-compose setup includes a fast-synced geth node. You can
> expect the `beacon_node` to log some eth1-related errors whilst the geth node
> boots and becomes synced. This will only happen on the first start of the
> compose environment or if geth loses sync.

### Installation complete!

In the next step you'll need to locate your `eth1_deposit_data.rlp` file from
your `.lighthouse/validators` directory.

The `./lighthouse` directory is in the root of the `lighthouse-docker`
repository. For example, if you ran Step 1 in `/home/karlm/` then you can find
your validator directory in
`/home/karlm/lighthouse-docker/.lighthouse/validators/`.

You can now go to [Become a Validator: Step 2](become-a-validator.html#2-submit-your-deposit-to-goerli).
