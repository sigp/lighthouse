# Importing from the Ethereum Staking Launch pad

The [Staking Launchpad](https://github.com/ethereum/eth2.0-deposit) is a website
from the Ethereum Foundation which guides users how to use the
[`eth2.0-deposit-cli`](https://github.com/ethereum/eth2.0-deposit-cli)
command-line program to generate consensus validator keys.

The keys that are generated from `eth2.0-deposit-cli` can be easily loaded into
a Lighthouse validator client (`lighthouse vc`). In fact, both of these
programs are designed to work with each other.

This guide will show the user how to import their keys into Lighthouse so they
can perform their duties as a validator. The guide assumes the user has already
[installed Lighthouse](./installation.md).

## Instructions

Whilst following the steps on the website, users are instructed to download the
[`eth2.0-deposit-cli`](https://github.com/ethereum/eth2.0-deposit-cli)
repository. This `eth2-deposit-cli` script will generate the validator BLS keys
into a `validator_keys` directory. We assume that the user's
present-working-directory is the `eth2-deposit-cli` repository (this is where
you will be if you just ran the `./deposit.sh` script from the Staking Launch pad
website). If this is not the case, simply change the `--directory` to point to
the `validator_keys` directory.

Now, assuming that the user is in the `eth2-deposit-cli` directory and they're
using the default (`~/.lighthouse/{network}/validators`) `validators` directory (specify a different one using
`--validators-dir` flag), they can follow these steps:

### 1. Run the `lighthouse account validator import` command.

Docker users should use the command from the [Docker](#docker)
section, all other users can use:


```bash
lighthouse --network mainnet account validator import --directory validator_keys
```

Note: The user must specify the consensus client network that they are importing the keys for using the `--network` flag.


After which they will be prompted for a password for each keystore discovered:

```
Keystore found at "validator_keys/keystore-m_12381_3600_0_0_0-1595406747.json":

 - Public key: 0xa5e8702533f6d66422e042a0bf3471ab9b302ce115633fa6fdc5643f804b6b4f1c33baf95f125ec21969a3b1e0dd9e56
 - UUID: 8ea4cf99-8719-43c5-9eda-e97b8a4e074f

If you enter a password it will be stored in validator_definitions.yml so that it is not required each time the validator client starts.

Enter a password, or press enter to omit a password:
```

The user can choose whether or not they'd like to store the validator password
in the [`validator_definitions.yml`](./validator-management.md) file. If the
password is *not* stored here, the validator client (`lighthouse vc`)
application will ask for the password each time it starts. This might be nice
for some users from a security perspective (i.e., if it is a shared computer),
however it means that if the validator client restarts, the user will be liable
to off-line penalties until they can enter the password. If the user trusts the
computer that is running the validator client and they are seeking maximum
validator rewards, we recommend entering a password at this point.

Once the process is done the user will see:

```
Successfully imported keystore.
Successfully updated validator_definitions.yml.

Successfully imported 1 validators (0 skipped).

WARNING: DO NOT USE THE ORIGINAL KEYSTORES TO VALIDATE WITH ANOTHER CLIENT, OR YOU WILL GET SLASHED..
```

The import process is complete!

### 2. Run the `lighthouse vc` command.

Now the keys are imported the user can start performing their validator duties
by running `lighthouse vc` and checking that their validator public key appears
as a `voting_pubkey` in one of the following logs:

```
INFO Enabled validator       voting_pubkey: 0xa5e8702533f6d66422e042a0bf3471ab9b302ce115633fa6fdc5643f804b6b4f1c33baf95f125ec21969a3b1e0dd9e56
```

Once this log appears (and there are no errors) the `lighthouse vc` application
will ensure that the validator starts performing its duties and being rewarded
by the protocol. There is no more input required from the user.

## Docker

The `import` command is a little more complex for Docker users, but the example
in this document can be substituted with:

```bash
docker run -it \
	-v $HOME/.lighthouse:/root/.lighthouse \
	-v $(pwd)/validator_keys:/root/validator_keys \
	sigp/lighthouse \
	lighthouse --network MY_NETWORK account validator import --directory /root/validator_keys
```

Here we use two `-v` volumes to attach:

- `~/.lighthouse` on the host to `/root/.lighthouse` in the Docker container.
- The `validator_keys` directory in the present working directory of the host
	to the `/root/validator_keys` directory of the Docker container.
