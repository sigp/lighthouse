---
name: devnet
description: Start a local devnet to test Lighthouse changes end-to-end. Runs a Kurtosis testnet with Geth + Lighthouse.
argument-hint: "[start|stop|status|test]"
---

# Local Devnet

Manage a local Ethereum testnet for end-to-end testing. Uses Kurtosis with Geth execution clients and Lighthouse consensus clients built from the current working tree.

## Prerequisites

Check that these tools are installed before proceeding:
```bash
docker --version && kurtosis version && yq --version
```
If any are missing, tell the user to install them and stop.

## Commands

### `/devnet start` — Start a basic devnet

1. Start the local testnet in CI mode (no Grafana/Dora):
   ```bash
   scripts/local_testnet/start_local_testnet.sh -c
   ```
   This builds a Docker image from the current working tree and deploys 4 beacon nodes + 4 validator clients + 4 Geth nodes.

2. Wait for the testnet to be healthy:
   ```bash
   kurtosis enclave inspect local-testnet
   ```

3. Report the enclave status, node endpoints, and any errors.

### `/devnet test` — Start devnet with automated tests

1. Start with Assertoor integration tests:
   ```bash
   scripts/local_testnet/start_local_testnet.sh -c -a
   ```
   This enables automated checks:
   - Block stability check
   - Block proposal check
   - Transaction test
   - Blob transaction test

2. Monitor Assertoor test results. Check the Assertoor service logs for pass/fail:
   ```bash
   kurtosis service logs local-testnet $(kurtosis enclave inspect local-testnet | grep assertoor | awk '{print $1}') 2>&1 | tail -100
   ```

3. Report which tests passed and which failed.

### `/devnet stop` — Stop the devnet

```bash
scripts/local_testnet/stop_local_testnet.sh
```

### `/devnet status` — Check devnet status

```bash
kurtosis enclave inspect local-testnet
```

Report: running services, their ports, and health status.

## Configuration

The testnet configuration is in `scripts/local_testnet/network_params.yaml`:
- 4 Lighthouse beacon nodes (2 supernodes, 2 regular)
- 4 Geth execution clients
- Fulu fork at epoch 0
- 3-second slot duration
- Debug logging

## Notes

- Building the Docker image takes several minutes on first run
- The testnet uses `spec-minimal` feature (not mainnet parameters)
- Use `-k` flag to keep the enclave when restarting: `scripts/local_testnet/start_local_testnet.sh -c -k`
- Logs are available via `kurtosis service logs local-testnet <service-name>`
- The testnet modifies `network_params.yaml` in-place when using `-a` or `-p` flags — reset with `git checkout scripts/local_testnet/network_params.yaml`
