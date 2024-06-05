# Simple Local Testnet

These scripts allow for running a small local testnet with a default of 4 beacon nodes, 4 validator clients and 4 geth execution clients using Kurtosis.
This setup can be useful for testing and development.

## Installation

1. Install [Docker](https://docs.docker.com/get-docker/). Verify that Docker has been successfully installed by running `sudo docker run hello-world`. 

1. Install [Kurtosis](https://docs.kurtosis.com/install/). Verify that Kurtosis has been successfully installed by running `kurtosis version` which should display the version.

1. Install [yq](https://github.com/mikefarah/yq). If you are on Ubuntu, you can install `yq` by running `sudo apt install yq -y`.

## Starting the testnet

To start a testnet:

```bash
cd ~
cd ./lighthouse/scripts/local_testnet
./start_local_testnet.sh
```

It will take an approximately 12 minutes to build. Once built, the testing will be started automatically. You will see a list of services running and "Started!" at the end.

To view all running services:

```bash
kurtosis enclave inspect local-testnet
```

To view the logs:

```bash
kurtosis service logs local-testnet $SERVICE_NAME
```

where `$SERVICE_NAME` is obtained by inspecting the running services above. For example, to view the logs of the first beacon node, validator client and geth:

```json
kurtosis service logs local-testnet -f cl-1-lighthouse-geth 
kurtosis service logs local-testnet -f vc-1-geth-lighthouse
kurtosis service logs local-testnet -f el-1-geth-lighthouse
```

## Stopping the testnet

To stop the testnet:

```bash
cd ~
cd ./lighthouse/scripts/local_testnet
./stop_local_testnet.sh
```

You will see `Local testnet stopped.` at the end.