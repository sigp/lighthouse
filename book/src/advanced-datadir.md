## Custom Data Directories

Users can override the default Lighthouse data directories (e.g., `~/.lighthouse/mainnet`) using the `--datadir` flag. The custom data directory mirrors the structure of any network specific default directory (e.g. `~/.lighthouse/mainnet`).

> Note: Users should specify different custom directories for different networks.

Below is an example flow for importing validator keys, running a beacon node and validator client using a custom data directory `/var/lib/my-custom-dir` for the Mainnet network.

```bash
lighthouse --network mainnet --datadir /var/lib/my-custom-dir account validator import --directory <PATH-TO-LAUNCHPAD-KEYS-DIRECTORY>
lighthouse --network mainnet --datadir /var/lib/my-custom-dir bn --staking
lighthouse --network mainnet --datadir /var/lib/my-custom-dir vc
```
The first step creates a `validators` directory under `/var/lib/my-custom-dir` which contains the imported keys and [`validator_definitions.yml`](./validator-management.md).
After that, we simply run the beacon chain and validator client with the custom dir path.

### Relative Paths

[#2682]: https://github.com/sigp/lighthouse/pull/2682
[#2846]: https://github.com/sigp/lighthouse/pull/2846

Prior to the introduction of [#2682][] and [#2846][] (releases v2.0.1 and earlier), Lighthouse would
not correctly parse relative paths from the `lighthouse bn --datadir` flag.

If the user provided a relative path (e.g., `--datadir here` or `--datadir ./here`), the `beacon`
directory would be split across two paths:

1. `~/here` (in the *home directory*), containing:
    - `chain_db`
    - `freezer_db`
1. `./here` (in the *present working directory*), containing:
    - `logs`
    - `network`

All versions released after the fix ([#2846][]) will default to storing all files in the present
working directory (i.e. `./here`). New users need not be concerned with the old behaviour.

For existing users which already have a split data directory, a backwards compatibility feature will
be applied. On start-up, if a split directory scenario is detected (i.e. `~/here` exists),
Lighthouse will continue to operate with split directories. In such a scenario, the following
harmless log will show:

```
WARN Legacy datadir location    location: "/home/user/datadir/beacon", msg: this occurs when using relative paths for a datadir location
```

In this case, the user could solve this warn by following these steps:

1. Stopping the BN process
1. Consolidating the legacy directory with the new one:
    - `mv /home/user/datadir/beacon/* $(pwd)/datadir/beacon`
    - Where `$(pwd)` is the present working directory for the Lighthouse binary
1. Removing the legacy directory:
    - `rm -r /home/user/datadir/beacon`
1. Restarting the BN process

Although there are no known issues with using backwards compatibility functionality, having split
directories is likely to cause confusion for users. Therefore, we recommend that affected users migrate
to a consolidated directory structure.
