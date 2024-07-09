#!/usr/bin/env bash

# Requires `docker`, `kurtosis`, `yq`

set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=local-testnet
NETWORK_PARAMS_FILE=$SCRIPT_DIR/network_params.yaml

BUILD_IMAGE=true
BUILDER_PROPOSALS=false
CI=false

# Get options
while getopts "e:b:n:phc" flag; do
  case "${flag}" in
    e) ENCLAVE_NAME=${OPTARG};;
    b) BUILD_IMAGE=${OPTARG};;
    n) NETWORK_PARAMS_FILE=${OPTARG};;
    p) BUILDER_PROPOSALS=true;;
    c) CI=true;;
    h)
        echo "Start a local testnet with kurtosis."
        echo
        echo "usage: $0 <Options>"
        echo
        echo "Options:"
        echo "   -e: enclave name                                default: $ENCLAVE_NAME"
        echo "   -b: whether to build Lighthouse docker image    default: $BUILD_IMAGE"
        echo "   -n: kurtosis network params file path           default: $NETWORK_PARAMS_FILE"
        echo "   -p: enable builder proposals"
        echo "   -c: CI mode, run without other additional services like Grafana and Dora explorer"
        echo "   -h: this help"
        exit
        ;;
  esac
done

LH_IMAGE_NAME=$(yq eval ".participants[0].cl_image" $NETWORK_PARAMS_FILE)

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
  yq eval '.participants[0].vc_extra_params = ["--builder-proposals"]' -i $NETWORK_PARAMS_FILE
  echo "--builder-proposals VC flag added to network_params.yaml"
fi

if [ "$CI" = true ]; then
  # TODO: run assertoor tests
  yq eval '.additional_services = []' -i $NETWORK_PARAMS_FILE
  echo "Running without additional services (CI mode)."
else
  yq eval '.additional_services = ["dora", "prometheus_grafana"]' -i $NETWORK_PARAMS_FILE
  echo "Additional services dora and prometheus_grafana added to network_params.yaml"
fi

if [ "$BUILD_IMAGE" = true ]; then
    echo "Building Lighthouse Docker image."
    ROOT_DIR="$SCRIPT_DIR/../.."
    docker build --build-arg FEATURES=portable -f $ROOT_DIR/Dockerfile -t $LH_IMAGE_NAME $ROOT_DIR
else
    echo "Not rebuilding Lighthouse Docker image."
fi

# Stop local testnet
kurtosis enclave rm -f $ENCLAVE_NAME 2>/dev/null || true

kurtosis run --enclave $ENCLAVE_NAME github.com/ethpandaops/ethereum-package --args-file $NETWORK_PARAMS_FILE

echo "Started!"
