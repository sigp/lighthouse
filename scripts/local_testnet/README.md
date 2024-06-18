# Simple Local Testnet

These scripts allow for running a small local testnet with a default of 4 beacon nodes, 4 validator clients and 4 geth execution clients using Kurtosis.
This setup can be useful for testing and development.

## Installation

1. Install [Docker](https://docs.docker.com/get-docker/). Verify that Docker has been successfully installed by running `sudo docker run hello-world`. 

1. Install [Kurtosis](https://docs.kurtosis.com/install/). Verify that Kurtosis has been successfully installed by running `kurtosis version` which should display the version.

1. Install [yq](https://github.com/mikefarah/yq). If you are on Ubuntu, you can install `yq` by running `sudo apt install yq -y`.

## Starting the testnet

To start a testnet, from the Lighthouse root repository:

```bash
cd ./scripts/local_testnet
./start_local_testnet.sh
```

It will build a Lighthouse docker image from the root of the directory and will take an approximately 12 minutes to complete. Once built, the testing will be started automatically. You will see a list of services running and "Started!" at the end. 
You can also select your own Lighthouse docker image to use by specifying it in `network_params.yml` under the `cl_image` key.
Full configuration reference for kurtosis is specified [here](https://github.com/ethpandaops/ethereum-package?tab=readme-ov-file#configuration).

To view all running services:

```bash
kurtosis enclave inspect local-testnet
```

To view the logs:

```bash
kurtosis service logs local-testnet $SERVICE_NAME
```

where `$SERVICE_NAME` is obtained by inspecting the running services above. For example, to view the logs of the first beacon node, validator client and geth:

```bash
kurtosis service logs local-testnet -f cl-1-lighthouse-geth 
kurtosis service logs local-testnet -f vc-1-geth-lighthouse
kurtosis service logs local-testnet -f el-1-geth-lighthouse
```

If you would like to save the logs, use the command:

```bash
kurtosis dump $OUTPUT_DIRECTORY
```

This will create a folder named `$OUTPUT_DIRECTORY` in the present working directory that contains all logs and other information. If you want the logs for a particular service and saved to a file named `logs.txt`:

```bash
kurtosis service logs local-testnet $SERVICE_NAME -a > logs.txt
```
where `$SERVICE_NAME` can be viewed by running `kurtosis enclave inspect local-testnet`.

Kurtosis comes with a Dora explorer which can be opened with:

```bash
open $(kurtosis port print local-testnet dora http)
```

Some testnet parameters can be varied by modifying the `network_params.yaml` file. Kurtosis also comes with a web UI which can be open with `kurtosis web`.

## Stopping the testnet

To stop the testnet, from the Lighthouse root repository:

```bash
cd ./scripts/local_testnet
./stop_local_testnet.sh
```

You will see "Local testnet stopped." at the end. 

## CLI options

The script comes with some CLI options, which can be viewed with `./start_local_testnet.sh --help`. One of the CLI options is to avoid rebuilding Lighthouse each time the testnet starts, which can be configured with the command:

```bash
./start_local_testnet.sh -b false
```