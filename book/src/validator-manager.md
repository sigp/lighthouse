# Validator Manager

[Ethereum Launchpad]: https://launchpad.ethereum.org/en/
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

- The validator manager generates deposit files compatible with the [Ethereum Launchpad]().
- Changes made with the validator manager do not require downtime for the VC.
- The "key cache" is preserved whenever a validator is added with the validator manager, this
    prevents long waits at start up when a new validator is added.

## Commands

### Create Validators

The `lighthouse validator-manager validators create` command accepts a mnemonic and produces a JSON
file containing validator keystores that can be imported with the [Import
Validators]() command.

For users that want to add validators to a VC from an existing mnemonic, this is the first half the
process which generates a *validator specifications* JSON file for the new validators. The second
half of the process is to upload those validator specifications to a VC (see [Import Validators]().
The command is split into two steps so that security-conscious validators can generate the validator
specifications on an "air-gapped" computer which is not connected to the Internet. Then, the
validator specifications file can be transferred to a VC for import. This means that the VC never
has access to the mnemonic, just the keystores with which it is concerned.

### Import Validators
