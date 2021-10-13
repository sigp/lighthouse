# Slashing Protection

The security of Ethereum 2.0's proof of stake protocol depends on penalties for misbehaviour, known
as _slashings_. Validators that sign conflicting messages (blocks or attestations), can be slashed
by other validators through the inclusion of a `ProposerSlashing` or `AttesterSlashing` on chain.

The Lighthouse validator client includes a mechanism to protect its validators against
accidental slashing, known as the slashing protection database. This database records every
block and attestation signed by validators, and the validator client uses this information to
avoid signing any slashable messages.

Lighthouse's slashing protection database is an SQLite database located at
`$datadir/validators/slashing_protection.sqlite` which is locked exclusively when the validator
client is running. In normal operation, this database will be automatically created and utilized,
meaning that your validators are kept safe by default.

If you are seeing errors related to slashing protection, it's important that you act slowly
and carefully to keep your validators safe. See the [Troubleshooting](#troubleshooting) section.

## Initialization

The database will be automatically created, and your validators registered with it when:

* Importing keys from another source (e.g. Launchpad, Teku, Prysm, `ethdo`).
  See [the docs on importing keys](./validator-import-launchpad.md).
* Creating keys using Lighthouse itself (`lighthouse account validator create`)
* Creating keys via the [validator client API](./api-vc.md).

## Avoiding Slashing

The slashing protection database is designed to protect against many common causes of slashing,
but is unable to prevent against some others.

Examples of circumstances where the slashing protection database is effective are:

* Accidentally running two validator clients on the same machine with the same datadir.
  The exclusive and transactional access to the database prevents the 2nd validator client
  from signing anything slashable (it won't even start).
* Deep re-orgs that cause the shuffling to change, prompting validators to re-attest in
  an epoch where they have already attested. The slashing protection checks all messages
  against the slashing conditions and will refuse to attest on the new chain until it is safe
  to do so (usually after one epoch).
* Importing keys and signing history from another client, where that history is complete.
  If you run another client and decide to switch to Lighthouse, you can export data from
  your client to be imported into Lighthouse's slashing protection database. See
  [Import and Export](#import-and-export).
* Misplacing `slashing_protection.sqlite` during a datadir change or migration between machines.
  By default Lighthouse will refuse to start if it finds validator keys that are not registered
  in the slashing protection database.

Examples where it is **ineffective** are:

* Running two validator client instances simultaneously. This could be two different
  clients (e.g. Lighthouse and Prysm) running on the same machine, two Lighthouse instances using
  different datadirs, or two clients on completely different machines (e.g. one on a cloud server
  and one running locally). You are responsible for ensuring that your validator keys are never
  running simultanously – the slashing protection DB **cannot protect you in this case**.
* Importing keys from another client without also importing voting history.
* If you use `--init-slashing-protection` to recreate a missing slashing protection database.

## Import and Export

Lighthouse supports the slashing protection interchange format described in [EIP-3076][]. An
interchange file is a record of blocks and attestations signed by a set of validator keys –
basically a portable slashing protection database!

With your validator client stopped, you can import a `.json` interchange file from another client
using this command:

```bash
lighthouse account validator slashing-protection import <my_interchange.json>
```

Instructions for exporting your existing client's database are out of scope for this document,
please check the other client's documentation for instructions.

When importing an interchange file, you still need to import the validator keystores themselves
separately, using the instructions for [importing keystores into
Lighthouse](./validator-import-launchpad.md).

---

You can export Lighthouse's database for use with another client with this command:

```
lighthouse account validator slashing-protection export <lighthouse_interchange.json>
```

The validator client needs to be stopped in order to export, to guarantee that the data exported is
up to date.

[EIP-3076]: https://eips.ethereum.org/EIPS/eip-3076

### How Import Works

Since version 1.6.0 Lighthouse will ignore any slashable data in the import data and will safely
update the low watermarks for blocks and attestations. It will store only the maximum-slot block
for each validator, and the maximum source/target attestation. This is faster than importing
all data while also being more resilient to repeated imports & stale data.

### Minification

The exporter can be configured to minify (shrink) the data it exports by keeping only the
maximum-slot and maximum-epoch messages. Provide the `--minify=true` flag:

```
lighthouse account validator slashing-protection export --minify=true <lighthouse_interchange.json>
```

This may make the file faster to import into other clients, but is unnecessary for Lighthouse to
Lighthouse transfers since v1.5.0.

## Troubleshooting

### Misplaced Slashing Database

If the slashing protection database cannot be found, it will manifest in an error like this:

```
Oct 12 14:41:26.415 CRIT Failed to start validator client        reason: Failed to open slashing protection database: SQLError("Unable to open database: Error(Some(\"unable to open database file: /home/karlm/.lighthouse/mainnet/validators/slashing_protection.sqlite\"))").
Ensure that `slashing_protection.sqlite` is in "/home/karlm/.lighthouse/mainnet/validators" folder
```

Usually this indicates that during some manual intervention the slashing database has been
misplaced. This error can also occur if you have upgraded from Lighthouse v0.2.x to v0.3.x without
moving the slashing protection database. If you have imported your keys into a new node, you should
never see this error (see [Initialization](#initialization)).

The safest way to remedy this error is to find your old slashing protection database and move
it to the correct location. In our example that would be
`~/.lighthouse/mainnet/validators/slashing_protection.sqlite`. You can search for your old database
using a tool like `find`, `fd`, or your file manager's GUI. Ask on the Lighthouse Discord if you're
not sure.

If you are absolutely 100% sure that you need to recreate the missing database, you can start
the Lighthouse validator client with the `--init-slashing-protection` flag. This flag is incredibly
dangerous and should not be used lightly, and we **strongly recommend** you try finding
your old slashing protection database before using it. If you do decide to use it, you should
wait at least 1 epoch (~7 minutes) from when your validator client was last actively signing
messages. If you suspect your node experienced a clock drift issue you should wait
longer. Remember that the inactivity penalty for being offline for even a day or so
is approximately equal to the rewards earned in a day. You will get slashed if you use
`--init-slashing-protection` incorrectly.

### Slashable Attestations and Re-orgs

Sometimes a re-org can cause the validator client to _attempt_ to sign something slashable,
in which case it will be blocked by slashing protection, resulting in a log like this:

```
Sep 29 15:15:05.303 CRIT Not signing slashable attestation       error: InvalidAttestation(DoubleVote(SignedAttestation { source_epoch: Epoch(0), target_epoch: Epoch(30), signing_root: 0x0c17be1f233b20341837ff183d21908cce73f22f86d5298c09401c6f37225f8a })), attestation: AttestationData { slot: Slot(974), index: 0, beacon_block_root: 0xa86a93ed808f96eb81a0cd7f46e3b3612cafe4bd0367aaf74e0563d82729e2dc, source: Checkpoint { epoch: Epoch(0), root: 0x0000000000000000000000000000000000000000000000000000000000000000 }, target: Checkpoint { epoch: Epoch(30), root: 0xcbe6901c0701a89e4cf508cfe1da2bb02805acfdfe4c39047a66052e2f1bb614 } }
```

This log is still marked as `CRIT` because in general it should occur only very rarely,
and _could_ indicate a serious error or misconfiguration (see [Avoiding Slashing](#avoiding-slashing)).

## Limitation of Liability

The Lighthouse developers do not guarantee the perfect functioning of this software, or accept
liability for any losses suffered. For more information see the [Lighthouse license][license].

[license]: https://github.com/sigp/lighthouse/blob/stable/LICENSE
