# Database Migrations

Lighthouse uses a versioned database schema to allow its database design to evolve over time.

Since beacon chain genesis in December 2020 there have been several database upgrades that have
been applied automatically and in a _backwards compatible_ way.

However, backwards compatibility does not imply the ability to _downgrade_ to a prior version of
Lighthouse after upgrading. To facilitate smooth downgrades, Lighthouse v2.3.0 and above includes a
command for applying database downgrades.

**Everything on this page applies to the Lighthouse _beacon node_, not to the
validator client or the slasher**.

## List of schema versions

| Lighthouse version | Release date | Schema version | Downgrade available? |
|--------------------|--------------|----------------|----------------------|
| v5.3.0             | Aug 2024 TBD | v22 TBD        | no (TBD)             |
| v5.2.0             | Jun 2024     | v19            | no                   |
| v5.1.0             | Mar 2024     | v19            | no                   |
| v5.0.0             | Feb 2024     | v19            | no                   |
| v4.6.0             | Dec 2023     | v19            | no                   |

> **Note**: All point releases (e.g. v4.4.1) are schema-compatible with the prior minor release
> (e.g. v4.4.0).

> **Note**: Even if no schema downgrade is available, it is still possible to move between versions
> that use the same schema. E.g. you can downgrade from v5.2.0 to v5.0.0 because both use schema
> v19.

> **Note**: Support for old schemas is gradually removed from newer versions of Lighthouse. We
usually do this after a major version has been out for a while and everyone has upgraded. Deprecated
schema versions for previous releases are archived under
[Full list of schema versions](#full-list-of-schema-versions). If you get stuck and are unable
to upgrade a **testnet** node to the latest version, sometimes it is possible to upgrade via an
intermediate version (e.g. upgrade from v3.5.0 to v4.6.0 via v4.0.1). This is never necessary
on mainnet.

## How to apply a database downgrade

To apply a downgrade you need to use the `lighthouse db migrate` command with the correct parameters.

1. Make sure you have a copy of the latest version of Lighthouse. This will be the version that
   knows about the latest schema change, and has the ability to revert it.
2. Work out the schema version you would like to downgrade to by checking the table above, or the [Full list of schema versions](#full-list-of-schema-versions) below. E.g. if you want to downgrade from v4.2.0, which upgraded the version from v16 to v17, then you'll want to downgrade to v16 in order to run v4.0.1.
3. **Ensure that downgrading is feasible**. Not all schema upgrades can be reverted, and some of
   them are time-sensitive. The release notes will state whether a downgrade is available and
   whether any caveats apply to it.
4. Work out the parameters for [Running `lighthouse db` correctly][run-correctly], including your
   Lighthouse user, your datadir and your network flag.
5. After stopping the beacon node, run the migrate command with the `--to` parameter set to the
   schema version you would like to downgrade to.

```bash
sudo -u "$LH_USER" lighthouse db migrate --to "$VERSION" --datadir "$LH_DATADIR" --network "$NET"
```

For example if you want to downgrade to Lighthouse v4.0.1 from v4.2.0 and you followed Somer Esat's guide, you would run:

```bash
sudo -u lighthousebeacon lighthouse db migrate --to 16 --datadir /var/lib/lighthouse --network mainnet
```

Where `lighthouse` is Lighthouse v4.2.0+. After the downgrade succeeds you can then replace your
global `lighthouse` binary with the older version and start your node again.

## How to apply a database upgrade

Database _upgrades_ happen automatically upon installing a new version of Lighthouse. We will
highlight in the release notes when a database upgrade is included, and make note of the schema
versions involved (e.g. v2.3.0 includes an upgrade from v8 to v9).

They can also be applied using the `--to` parameter to `lighthouse db migrate`. See the section
on downgrades above.

## How to check the schema version

To check the schema version of a running Lighthouse instance you can use the HTTP API:

```bash
curl "http://localhost:5052/lighthouse/database/info" | jq
```

```json
{
  "schema_version": 16,
  "config": {
    "slots_per_restore_point": 8192,
    "slots_per_restore_point_set_explicitly": false,
    "block_cache_size": 5,
    "historic_state_cache_size": 1,
    "compact_on_init": false,
    "compact_on_prune": true,
    "prune_payloads": true
  },
  "split": {
    "slot": "5485952",
    "state_root": "0xcfe5d41e6ab5a9dab0de00d89d97ae55ecaeed3b08e4acda836e69b2bef698b4"
  },
  "anchor": {
    "anchor_slot": "5414688",
    "oldest_block_slot": "0",
    "oldest_block_parent": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "state_upper_limit": "5414912",
    "state_lower_limit": "8192"
  }
}
```

The `schema_version` key indicates that this database is using schema version 16.

Alternatively, you can check the schema version with the `lighthouse db` command.

```bash
sudo -u lighthousebeacon lighthouse db version --datadir /var/lib/lighthouse --network mainnet
```

See the section on [Running `lighthouse db` correctly][run-correctly] for details.

## How to run `lighthouse db` correctly

Several conditions need to be met in order to run `lighthouse db`:

1. The beacon node must be **stopped** (not running). If you are using systemd a command like
   `sudo systemctl stop lighthousebeacon` will accomplish this.
2. The command must run as the user that owns the beacon node database. If you are using systemd then
   your beacon node might run as a user called `lighthousebeacon`.
3. The `--datadir` flag must be set to the location of the Lighthouse data directory.
4. The `--network` flag must be set to the correct network, e.g. `mainnet`, `holesky` or `sepolia`.

The general form for a `lighthouse db` command is:

```bash
sudo -u "$LH_USER" lighthouse db version --datadir "$LH_DATADIR" --network "$NET"
```

If you followed Somer Esat's guide for mainnet:

```bash
sudo systemctl stop lighthousebeacon
```

```bash
sudo -u lighthousebeacon lighthouse db version --datadir /var/lib/lighthouse --network mainnet
```

If you followed the CoinCashew guide for mainnet:

```bash
sudo systemctl stop beacon-chain
```

```bash
lighthouse db version --network mainnet
```

[run-correctly]: #how-to-run-lighthouse-db-correctly

## How to prune historic states

Pruning historic states helps in managing the disk space used by the Lighthouse beacon node by removing old beacon
states from the freezer database. This can be especially useful when the database has accumulated a significant amount
of historic data. This command is intended for nodes synced before 4.4.1, as newly synced nodes no longer store historic states by default.

Here are the steps to prune historic states:

1. Before running the prune command, make sure that the Lighthouse beacon node is not running. If you are using systemd, you might stop the Lighthouse beacon node with a command like:

   ```bash
    sudo systemctl stop lighthousebeacon
    ```

2. Use the `prune-states` command to prune the historic states. You can do a test run without the `--confirm` flag to check that the database can be pruned:

   ```bash
    sudo -u "$LH_USER" lighthouse db prune-states --datadir "$LH_DATADIR" --network "$NET"
    ```

   If pruning is available, Lighthouse will log:

   ```text
   INFO Ready to prune states
   WARN Pruning states is irreversible
   WARN Re-run this command with --confirm to commit to state deletion
   INFO Nothing has been pruned on this run
   ```

3. If you are ready to prune the states irreversibly, add the `--confirm` flag to commit the changes:

   ```bash
    sudo -u "$LH_USER" lighthouse db prune-states --confirm --datadir "$LH_DATADIR" --network "$NET"
    ```

   The `--confirm` flag ensures that you are aware the action is irreversible, and historic states will be permanently removed. Lighthouse will log:

   ```text
   INFO Historic states pruned successfully
   ```

4. After successfully pruning the historic states, you can restart the Lighthouse beacon node:

   ```bash
    sudo systemctl start lighthousebeacon
    ```

## Full list of schema versions

| Lighthouse version | Release date | Schema version | Downgrade available?                |
|--------------------|--------------|----------------|-------------------------------------|
| v5.2.0             | Jun 2024     | v19            | yes before Deneb using <= v5.2.1    |
| v5.1.0             | Mar 2024     | v19            | yes before Deneb using <= v5.2.1    |
| v5.0.0             | Feb 2024     | v19            | yes before Deneb using <= v5.2.1    |
| v4.6.0             | Dec 2023     | v19            | yes before Deneb using <= v5.2.1    |
| v4.6.0-rc.0        | Dec 2023     | v18            | yes before Deneb using <= v5.2.1    |
| v4.5.0             | Sep 2023     | v17            | yes using <= v5.2.1                 |
| v4.4.0             | Aug 2023     | v17            | yes using <= v5.2.1                 |
| v4.3.0             | Jul 2023     | v17            | yes using <= v5.2.1                 |
| v4.2.0             | May 2023     | v17            | yes using <= v5.2.1                 |
| v4.1.0             | Apr 2023     | v16            | yes before Capella using <= v4.5.0  |
| v4.0.1             | Mar 2023     | v16            | yes before Capella using <= v4.5.0  |
| v3.5.0             | Feb 2023     | v15            | yes before Capella using <= v4.5.0  |
| v3.4.0             | Jan 2023     | v13            | yes using <= 4.5.0                  |
| v3.3.0             | Nov 2022     | v13            | yes using <= 4.5.0                  |
| v3.2.0             | Oct 2022     | v12            | yes using <= 4.5.0                  |
| v3.1.0             | Sep 2022     | v12            | yes using <= 4.5.0                  |
| v3.0.0             | Aug 2022     | v11            | yes using <= 4.5.0                  |
| v2.5.0             | Aug 2022     | v11            | yes using <= 4.5.0                  |
| v2.4.0             | Jul 2022     | v9             | yes using <= v3.3.0                 |
| v2.3.0             | May 2022     | v9             | yes using <= v3.3.0                 |
| v2.2.0             | Apr 2022     | v8             | no                                  |
| v2.1.0             | Jan 2022     | v8             | no                                  |
| v2.0.0             | Oct 2021     | v5             | no                                  |
