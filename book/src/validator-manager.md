# Validator Manager

[Ethereum Staking Launchpad]: https://launchpad.ethereum.org/en/
[Import Validators]: #import-validators

## Introduction

The `lighthouse validator-manager` tool provides utilities for managing validators on a *running*
Lighthouse Validator Client. The validator manager performs operations via the HTTP API of the
validator client (VC). Due to limitations of the
[keymanager-APIs](https://ethereum.github.io/keymanager-APIs/), only Lighthouse VCs are fully
supported by this command.

The validator manager tool is similar to the `lighthouse account-manager` tool,
except the latter creates files that will be read by the VC next time it starts
whilst the former makes instant changes to a live VC.

The `account-manager` is ideal for importing keys created with the
[staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli). On the
other hand, the `validator-manager` is ideal for moving existing validators
between two VCs or for advanced users to create validators at scale with less
downtime.

The `validator-manager` boasts the following features:

- One-line command to arbitrarily move validators between two VCs, maintaining the slashing protection database.
- Generates deposit files compatible with the [Ethereum Staking Launchpad][].
- Generally involves zero or very little downtime.
- The "key cache" is preserved whenever a validator is added with the validator
    manager, preventing long waits at start up when a new validator is added.

## Guides

- [Creating and importing validators using the `create` and `import` commands.](./validator-manager-create.md)
- [Moving validators between two VCs using the `move` command.](./validator-manager-move.md)