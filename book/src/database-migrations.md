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
| v2.0.0             | Oct 2021     | v5             | no                   |
| v2.1.0             | Jan 2022     | v8             | no                   |
| v2.2.0             | Apr 2022     | v8             | no                   |
| v2.3.0             | May 2022     | v9             | yes (pre Bellatrix)  |
| v2.4.0             | Jul 2022     | v9             | yes (pre Bellatrix)  |
| v2.5.0             | Aug 2022     | v11            | yes                  |
| v3.0.0             | Aug 2022     | v11            | yes                  |
| v3.1.0             | Sep 2022     | v12            | yes                  |
| v3.2.0             | Oct 2022     | v12            | yes                  |
| v3.3.0             | TBD          | v13            | yes                  |

> **Note**: All point releases (e.g. v2.3.1) are schema-compatible with the prior minor release
> (e.g. v2.3.0).

## How to apply a database downgrade

To apply a downgrade you need to use the `lighthouse db migrate` command with the correct parameters.

1. Make sure you have a copy of the latest version of Lighthouse. This will be the version that
   knows about the latest schema change, and has the ability to revert it.
2. Work out the schema version you would like to downgrade to by checking the table above, or the
   Lighthouse release notes. E.g. if you want to downgrade from v2.3.0, which upgraded the version
   from v8 to v9, then you'll want to _downgrade_ to v8 in order to run v2.2.x or earlier.
3. **Ensure that downgrading is feasible**. Not all schema upgrades can be reverted, and some of
   them are time-sensitive. The release notes will state whether a downgrade is available and
   whether any caveats apply to it.
4. Work out the parameters for [Running `lighthouse db` correctly][run-correctly], including your
   Lighthouse user, your datadir and your network flag.
5. After stopping the beacon node, run the migrate command with the `--to` parameter set to the
   schema version you would like to downgrade to.

```
sudo -u "$LH_USER" lighthouse db migrate --to "$VERSION" --datadir "$LH_DATADIR" --network "$NET"
```

For example if you want to downgrade to Lighthouse v2.1 or v2.2 from v2.3 and you followed Somer
Esat's guide, you would run:

```
sudo -u lighthousebeacon lighthouse db migrate --to 8 --datadir /var/lib/lighthouse --network mainnet
```

Where `lighthouse` is Lighthouse v2.3.0+. After the downgrade succeeds you can then replace your
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
curl "http://localhost:5052/lighthouse/database/info"
```

```json
{
  "schema_version": 8,
  "config": {
    "slots_per_restore_point": 8192,
    "slots_per_restore_point_set_explicitly": true,
    "block_cache_size": 5,
    "compact_on_init": false,
    "compact_on_prune": true
  }
}
```

The `schema_version` key indicates that this database is using schema version 8.

Alternatively, you can check the schema version with the `lighthouse db` command.

```
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
4. The `--network` flag must be set to the correct network, e.g. `mainnet`, `prater` or `ropsten`.

The general form for a `lighthouse db` command is:

```
sudo -u "$LH_USER" lighthouse db version --datadir "$LH_DATADIR" --network "$NET"
```

If you followed Somer Esat's guide for mainnet:

```
sudo systemctl stop lighthousebeacon
```
```
sudo -u lighthousebeacon lighthouse db version --datadir /var/lib/lighthouse --network mainnet
```

If you followed the CoinCashew guide for mainnet:

```
sudo systemctl stop beacon-chain
```
```
lighthouse db version --network mainnet
```

[run-correctly]: #how-to-run-lighthouse-db-correctly
