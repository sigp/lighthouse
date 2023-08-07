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
    --network mainnet \
    --first-index 0 \
    --count 2 \
    --eth1-withdrawal-address <ADDRESS> \
    --suggested-fee-recipient <ADDRESS> \
    --output-path ./
```
> If the flag `--first-index` is not provided, it will default to using index 0.
> The `--suggested-fee-recipient` flag may be omitted to use whatever default
> value the VC uses. It does not necessarily need to be identical to
> `--eth1-withdrawal-address`.
> The command will create the `deposits.json` and `validators.json` in the present working directory. If you would like these files to be created in a different directory, change the value of `output-path`, for example `--output-path /desired/directory`. The directory will be created if the path does not exist.

Then, import the validators to a running VC with:

```bash
lighthouse \
    validator-manager \
    import \
    --validators-file validators.json \
    --vc-token <API-TOKEN-PATH>
```
> This is assuming that `validators.json` is in the present working directory. If it is not, insert the directory of the file.
> Be sure to remove `./validators.json` after the import is successful since it
> contains unencrypted validator keystores.

## Detailed Guide

This guide will create two validators and import them to a VC. For simplicity,
the same host will be used to generate the keys and run the VC. In reality,
users may want to perform the `create` command on an air-gapped machine and then
move the `validators.json` and `deposits.json` files to an Internet-connected
host. This would help protect the mnemonic from being exposed to the Internet.

### 1. Create the Validators

Run the `create` command, substituting `<ADDRESS>` for an execution address that
you control. This is where all the staked ETH and rewards will ultimately
reside, so it's very important that this address is secure, accessible and
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
- `--http-port 5062`
- `--enable-doppelganger-protection`

Therefore, the VC command might look like:

```bash
lighthouse \
    vc \
    --http \
    --http-port 5062 \
    --enable-doppelganger-protection
```

In order to import the validators, the location of the VC `api-token.txt` file
must be known. The location of the file varies, but it is located in the
"validator directory" of your data directory. For example:
`~/.lighthouse/mainnet/validators/api-token.txt`. We will use `<API-TOKEN-PATH>`
to subsitute this value. If you are unsure of the `api-token.txt` path, you can run `curl http://localhost:5062/lighthouse/auth` which will show the path.


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
Starting to submit 2 validators to VC, each validator may take several seconds
Uploaded keystore 1 of 2 to the VC
Uploaded keystore 2 of 2 to the VC
```

The user should now *securely* delete the `validators.json` file (e.g., `shred -u validators.json`).
The `validators.json` contains the unencrypted validator keys and must not be
shared with anyone.
At the same time, `lighthouse vc` will log:
```bash
INFO Importing keystores via standard HTTP API, count: 1
WARN No slashing protection data provided with keystores
INFO Enabled validator                       voting_pubkey: 0xab6e29f1b98fedfca878edce2b471f1b5ee58ee4c3bd216201f98254ef6f6eac40a53d74c8b7da54f51d3e85cacae92f, signing_method: local_keystore
INFO Modified key_cache saved successfully
```
The WARN message means that the `validators.json` file does not contain the slashing protection data. This is normal if you are starting a new validator. The flag `--enable-doppelganger-protection` will also protect users from potential slashing risk. 
The validators will now go through 2-3 epochs of [doppelganger
protection](./validator-doppelganger.md) and will automatically start performing
their duties when they are deposited and activated. 

If the host VC contains the same public key as the `validators.json` file, an error will be shown and the `import` process will stop:

```bash
Duplicate validator   0xab6e29f1b98fedfca878edce2b471f1b5ee58ee4c3bd216201f98254ef6f6eac40a53d74c8b7da54f51d3e85cacae92f already exists on the destination validator client. This may indicate that some validators are running in two places at once, which can lead to slashing. If you are certain that there is no risk, add the --ignore-duplicates flag.
Err(DuplicateValidator(0xab6e29f1b98fedfca878edce2b471f1b5ee58ee4c3bd216201f98254ef6f6eac40a53d74c8b7da54f51d3e85cacae92f))
```

If you are certain that it is safe, you can add the flag `--ignore-duplicates` in the `import` command. The command becomes:

```bash
lighthouse \
    validator-manager \
    import \
    --validators-file validators.json \
    --vc-token <API-TOKEN-PATH> \
    --ignore-duplicates
```
and the output will be as follows:

```bash
Duplicate validators are ignored, ignoring 0xab6e29f1b98fedfca878edce2b471f1b5ee58ee4c3bd216201f98254ef6f6eac40a53d74c8b7da54f51d3e85cacae92f which exists on the destination validator client
Re-uploaded keystore 1 of 6 to the VC
```

The guide is complete.