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
