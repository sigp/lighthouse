# File Config

Load config from a YAML or TOML formatted file using the `--config-file` flag.  To override an option
specified in the configuration file, specify the same option in the command line. Separate config
files must be used for the beacon node and validator client.

Things to keep in mind:
- Each config filename must end in `.toml`, `.yml`, or `.yaml`.
- A flag will be enabled if **any** value is set for it in the config file. Our examples use `true` for clarity.
- If a flag is set in a config file, it **cannot** be overridden to false via command line arguments.
- We **do not** currently support loading config for any account management commands from file (`lighthouse account_manager` or `lighthouse am`).

### Examples
The following command:
```bash
$ lighthouse --debug-level debug beacon_node --port 8000 --http --http-port 6052 --eth1-endpoints "http://localhost:8545,http://localhost:9545"
```
Would be equivalent to this YAML config:
```bash
$ lighthouse beacon_node --config-file ./beacon-config.yaml
```
```yaml
debug-level: "debug"
port: 8000
http-port: 6052
staking: true
eth1-endpoints: ["http://localhost:8545", "http://localhost:9545"]
```
And this TOML config:
```bash
$ lighthouse beacon_node --config-file ./beacon-config.toml
```
```toml
debug-level = "debug"
port = 8000
http-port = 6052
staking = true
eth1-endpoints = ["http://localhost:8545", "http://localhost:9545"]
```