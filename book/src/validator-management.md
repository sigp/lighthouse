# Validator Management

The `lighthouse vc` command starts a *validator client* instance which connects
to a beacon node to perform the duties of a staked validator.

This document provides information on how the validator client discovers the
validators it will act for and how it obtains their cryptographic
signatures.

Users that create validators using the `lighthouse account` tool in the
standard directories and do not start their `lighthouse vc` with the
`--disable-auto-discover` flag should not need to understand the contents of
this document. However, users with more complex needs may find this document
useful.

The [lighthouse validator-manager](./validator-manager.md) command can be used
to create and import validators to a Lighthouse VC. It can also be used to move
validators between two Lighthouse VCs.

## Introducing the `validator_definitions.yml` file

The `validator_definitions.yml` file is located in the `validator-dir`, which
defaults to `~/.lighthouse/{network}/validators`. It is a
[YAML](https://en.wikipedia.org/wiki/YAML) encoded file defining exactly which
validators the validator client will (and won't) act for.

### Example

Here's an example file with two validators:

```yaml
---
- enabled: true
  voting_public_key: "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007
- enabled: false
  voting_public_key: "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477/voting-keystore.json
  voting_keystore_password: myStrongpa55word123&$
```
In this example we can see two validators:

- A validator identified by the `0x87a5...` public key which is enabled.
- Another validator identified by the `0x0xa556...` public key which is **not** enabled.

### Fields

Each permitted field of the file is listed below for reference:

- `enabled`: A `true`/`false` indicating if the validator client should consider this
	validator "enabled".
- `voting_public_key`: A validator public key.
- `type`: How the validator signs messages (this can be `local_keystore` or `web3signer` (see [Web3Signer](./validator-web3signer.md))).
- `voting_keystore_path`: The path to a EIP-2335 keystore.
- `voting_keystore_password_path`: The path to the password for the EIP-2335 keystore.
- `voting_keystore_password`: The password to the EIP-2335 keystore.

> **Note**: Either `voting_keystore_password_path` or `voting_keystore_password` *must* be
> supplied. If both are supplied, `voting_keystore_password_path` is ignored.

## Populating the `validator_definitions.yml` file

When a validator client starts and the `validator_definitions.yml` file doesn't
exist, a new file will be created. If the `--disable-auto-discover` flag is
provided, the new file will be empty and the validator client will not start
any validators. If the `--disable-auto-discover` flag is **not** provided, an
*automatic validator discovery* routine will start (more on that later). To
recap:

- `lighthouse vc`: validators are automatically discovered.
- `lighthouse vc --disable-auto-discover`: validators are **not** automatically discovered.

### Automatic validator discovery

When the `--disable-auto-discover` flag is **not** provided, the validator client will search the
`validator-dir` for validators and add any *new* validators to the
`validator_definitions.yml` with `enabled: true`.

The routine for this search begins in the `validator-dir`, where it obtains a
list of all files in that directory and all sub-directories (i.e., recursive
directory-tree search). For each file named `voting-keystore.json` it creates a
new validator definition by the following process:

1. Set `enabled` to `true`.
1. Set `voting_public_key` to the `pubkey` value from the `voting-keystore.json`.
1. Set `type` to `local_keystore`.
1. Set `voting_keystore_path` to the full path of the discovered keystore.
1. Set `voting_keystore_password_path` to be a file in the `secrets-dir` with a
name identical to the `voting_public_key` value.

#### Discovery Example

Let's assume the following directory structure:

```
~/.lighthouse/{network}/validators
├── john
│   └── voting-keystore.json
├── sally
│   ├── one
│   │   └── voting-keystore.json
│   ├── three
│   │   └── my-voting-keystore.json
│   └── two
│       └── voting-keystore.json
└── slashing_protection.sqlite
```

There is no `validator_definitions.yml` file present, so we can run `lighthouse
vc` (**without** `--disable-auto-discover`) and it will create the following `validator_definitions.yml`:

```yaml
---
- enabled: true
  voting_public_key: "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/sally/one/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477
- enabled: true
  voting_public_key: "0xaa440c566fcf34dedf233baf56cf5fb05bb420d9663b4208272545608c27c13d5b08174518c758ecd814f158f2b4a337"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/sally/two/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0xaa440c566fcf34dedf233baf56cf5fb05bb420d9663b4208272545608c27c13d5b08174518c758ecd814f158f2b4a337
- enabled: true
  voting_public_key: "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/john/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007
```

All `voting-keystore.json` files have been detected and added to the file.
Notably, the `sally/three/my-voting-keystore.json` file was *not* added to the
file, since the file name is not exactly `voting-keystore.json`.

In order for the validator client to decrypt the validators, they will need to
ensure their `secrets-dir` is organised as below:

```
~/.lighthouse/{network}/secrets
├── 0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477
├── 0xaa440c566fcf34dedf233baf56cf5fb05bb420d9663b4208272545608c27c13d5b08174518c758ecd814f158f2b4a337
└── 0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007
```


### Manual configuration

The automatic validator discovery process works out-of-the-box with validators
that are created using the `lighthouse account validator new` command. The
details of this process are only interesting to those who are using keystores
generated with another tool or have a non-standard requirements.

If you are one of these users, manually edit the `validator_definitions.yml`
file to suit your requirements. If the file is poorly formatted or any one of
the validators is unable to be initialized, the validator client will refuse to
start.

## How the `validator_definitions.yml` file is processed

If a validator client were to start using the [first example
`validator_definitions.yml` file](#example) it would print the following log,
acknowledging there are two validators and one is disabled:

```
INFO Initialized validators                  enabled: 1, disabled: 1
```

The validator client will simply ignore the disabled validator. However, for
the active validator, the validator client will:

1. Load an EIP-2335 keystore from the `voting_keystore_path`.
1. If the `voting_keystore_password` field is present, use it as the keystore
   password. Otherwise, attempt to read the file at
   `voting_keystore_password_path` and use the contents as the keystore
   password.
1. Use the keystore password to decrypt the keystore and obtain a BLS keypair.
1. Verify that the decrypted BLS keypair matches the `voting_public_key`.
1.  Create a `voting-keystore.json.lock` file adjacent to the
`voting_keystore_path`, indicating that the voting keystore is in-use and
should not be opened by another process.
1. Proceed to act for that validator, creating blocks and attestations if/when required.

If there is an error during any of these steps (e.g., a file is missing or
corrupt), the validator client will log an error and continue to attempt to
process other validators.

When the validator client exits (or the validator is deactivated), it will
remove the `voting-keystore.json.lock` to indicate that the keystore is free for use again.
