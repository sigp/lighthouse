#!/usr/bin/env bash

# Requires `docker`, `kurtosis`, `yq`

set -Eeuo pipefail

ENCLAVE_NAME=local-testnet
BUILD_IMAGE=true
BUILDER_PROPOSALS=false
CI=false

# Get options
while getopts "b:phc" flag; do
  case "${flag}" in
    b) BUILD_IMAGE=${OPTARG};;
    p) BUILDER_PROPOSALS=true;;
    c) CI=true;;
    h)
        echo "Start a local testnet with kurtosis."
        echo
        echo "usage: $0 <Options>"
        echo
        echo "Options:"
        echo "   -b: whether to build Lighthouse docker image    default: $BUILD_IMAGE"
        echo "   -p: enable builder proposals"
        echo "   -c: CI mode, run without other additional services like Grafana and Dora explorer"
        echo "   -h: this help"
        exit
        ;;
  esac
done

if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker and try again."
    exit 1
fi

if ! command -v kurtosis &> /dev/null; then
    echo "kurtosis command not found. Please install kurtosis and try again."
    exit
fi

if ! command -v yq &> /dev/null; then
    echo "yq not found. Please install yq and try again."
fi

if [ "$BUILDER_PROPOSALS" = true ]; then
  yq eval '.participants[0].vc_extra_params = ["--builder-proposals"]' -i ./network_params.yaml
  echo "--builder-proposals VC flag added to network_params.yaml"
fi

if [ "$CI" = true ]; then
  # TODO: run assertoor tests
  yq eval '.additional_services = []' -i ./network_params.yaml
  echo "Running without additional services (CI mode)."
else
  yq eval '.additional_services = ["dora", "prometheus_grafana"]' -i ./network_params.yaml
  echo "Additional services dora and prometheus_grafana added to network_params.yaml"
fi

if [ "$BUILD_IMAGE" = true ]; then
    echo "Building Lighthouse Docker image."
    ROOT_DIR='../..'
    docker build --build-arg FEATURES=portable -f $ROOT_DIR/Dockerfile -t lighthouse:local $ROOT_DIR
else
    echo "Not rebuilding Lighthouse Docker image."
fi

# Stop local testnet
kurtosis enclave rm -f $ENCLAVE_NAME 2>/dev/null || true

kurtosis run --enclave $ENCLAVE_NAME github.com/kurtosis-tech/ethereum-package --args-file ./network_params.yaml

echo "Started!"
