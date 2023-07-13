# Validator Manager

[Ethereum Staking Launchpad]: https://launchpad.ethereum.org/en/
[Import Validators]: #import-validators

## Introduction

The `lighthouse validator-manager` tool provides utilities for managing validators on a running
Lighthouse Validator Client. The validator manager performs operations via the HTTP API of the
validator client (VC). Due to limitations of the
[keymanager-APIs](https://ethereum.github.io/keymanager-APIs/), only Lighthouse VCs are fully
supported by this command.

The validator manager tool is similar to the `lighthouse account-manager` tool, except the latter
creates files that will be read by the VC next time it starts rather than making instant changes to
a live VC. The validator manager is generally superior to the account manager for the following
(non-exhaustive) reasons:

- The validator manager generates deposit files compatible with the [Ethereum Staking Launchpad]().
- Changes made with the validator manager do not require downtime for the VC.
- The "key cache" is preserved whenever a validator is added with the validator manager, this
    prevents long waits at start up when a new validator is added.

### Validator Manager Documentation

- [Creating and importing validators using the `create` and `import` commands](./validator-manager-create.md)
- [Moving validators between two VCs using the `move` command](./validator-manager.md)