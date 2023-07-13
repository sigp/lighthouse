# Creating and Importing Validators

[Ethereum Staking Launchpad]: https://launchpad.ethereum.org/en/

The `lighthouse validator-manager create` command derives validators from a
mnemonic and produces two files:

- `validators.json`: the keystores and passwords for the newly generated
    validators, in JSON format.
- `deposits.json`: a JSON file of the same format as
    [staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) which can
    be used for deposit submission via the [Ethereum Staking
    Launchpad][].

The `lighthouse validator-manager import` command accepts a `validators.json`
file (from the `create` command) and submits those validators to a running
Lighthouse Validator Client via the HTTP API.

These two commands enable a workflow of:

1. Creating the validators via the `create` command.
1. Importing the validators via the `import` command.
1. Depositing validators via the [Ethereum Staking
    Launchpad][].

The separation of the `create` and `import` commands allows for running the
`create` command on an air-gapped host whilst performing the `import` command on
an internet-connected host.

The `create` and `import` commands are recommended for advanced users who are
familiar with command line tools and the practicalities of managing sensitive
cryptographic material. **We recommend that novice users follow the workflow on
[Ethereum Staking Launchpad][] rather than using the `create` and `import`
commands.**

## Simple Example

Create validators from a mnemonic with:

```bash
lighthouse \
    validator-manager \
    create \
    --first-index 0 \
    --count 2 \
    --eth1-withdrawal-address <ADDRESS> \
    --suggested-fee-recipient <ADDRESS> \
    --output-path ./
```

> The `--suggested-fee-recipient` flag may be omitted to use whatever default
> value the VC uses. It does not necessarily need to be idential to
> `--eth1-withdrawal-address`.

Then, import the validators to a running VC with:

```bash
lighthouse \
    validator-manager \
    import \
    --validators-file validators.json \
    --vc-token <API-TOKEN-PATH>
```

> Be sure to remove `./validators.json` after the import is successful since it
> contains unencrypted validator keystores.

## Detailed Guide

This guide will create two validators and import them to a VC. For simplicity,
the same host will be used to generate the keys and run the VC. In reality,
users may want to perform the `import` command on an air-gapped machine and then
move the `validators.json` and `deposits.json` files to an Internet-connected
host. This would help protect the mnemonic from being exposed to the Internet.

### 1. Create the Validators

Run the `create` command, subsituting `<ADDRESS>` for an execution address that
you control. This is where all the staked ETH and rewards will ultimately
reside, so it's very important that this address is secure, acessible and
backed-up. The `create` command:

```bash
lighthouse \
    validator-manager \
    create \
    --first-index 0 \
    --count 2 \
    --eth1-withdrawal-address <ADDRESS> \
    --output-path ./
```

If successful, the command output will appear like below:

```bash
Running validator manager for mainnet network

Enter the mnemonic phrase:
<REDACTED>
Valid mnemonic provided.

Starting derivation of 2 keystores. Each keystore may take several seconds.
Completed 1/2: 0x8885c29b8f88ee9b9a37b480fd4384fed74bda33d85bc8171a904847e65688b6c9bb4362d6597fd30109fb2def6c3ae4
Completed 2/2: 0xa262dae3dcd2b2e280af534effa16bedb27c06f2959e114d53bd2a248ca324a018dc73179899a066149471a94a1bc92f
Keystore generation complete
Writing "./validators.json"
Writing "./deposits.json"
```

This command will create validators at indices `0, 1`. The exact indices created
can be influenced with the `--first-index` and `--count` flags. Use these flags
with caution to prevent creating the same validator twice, this may result in a
slashing!

The command will create two files:

- `./deposits.json`: this file does *not* contain sensitive information and may be uploaded to the [Ethereum Staking Launchpad].
- `./validators.json`: this file contains **sensitive unencrypted validator keys, do not share it with anyone or upload it to any website**.

### 2. Import the validators

The VC which will receive the validators needs to have the following flags at a minimum:

- `--http`
- `--unencrypted-http-transport`
- `--http-address 127.0.0.1`
- `--http-port 5062`
- `--enable-doppelganger-protection`

Therefore, the VC command might look like:

```bash
lighthouse \
    vc \
    --http \
    --unencrypted-http-transport \
    --http-address 127.0.0.1 \
    --http-port 5062 \
    --enable-doppelganger-protection
```

In order to import the validators, the location of the VC `api-token.txt` file
must be known. The location of the file varies, but it is located in the
"validator directory" of your data directory. For example:
`~/.lighthouse/mainnet/validators/api-token.txt`. We will use `<API-TOKEN-PATH>`
to subsitute this value.


Once the VC is running, use the `import` command to import the validators to the VC:

```bash
lighthouse \
    validator-manager \
    import \
    --validators-file validators.json \
    --vc-token <API-TOKEN-PATH>
```

If successful, the command output will appear like below:

```bash
Running validator manager for mainnet network
Validator client is reachable at http://localhost:5062/ and reports 0 validators
Starting to submit validators 2 to VC, each validator may take several seconds
Uploaded keystore 1 of 2 to the VC
Uploaded keystore 2 of 2 to the VC
```

The user should now *securely* delete the `validators.json` file (e.g., `shred -u validators.json`).
The `validators.json` contains the unencrypted validator keys and must not be
shared with anyone.

The validators will now go through 3-4 epochs of [doppelganger
protection](./validator-doppelganger.md) and will automatically start performing
their duties when they are deposited and activated. The guide is complete.