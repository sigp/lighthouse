#!/usr/bin/env bash

#
# Starts a beacon node based upon a genesis state created by `./setup.sh`.
#

set -Eeuo pipefail

source ./vars.env

SUBSCRIBE_ALL_SUBNETS=
DEBUG_LEVEL=${DEBUG_LEVEL:-info}

# Get options
while getopts "d:sh" flag; do
  case "${flag}" in
    d) DEBUG_LEVEL=${OPTARG};;
    s) SUBSCRIBE_ALL_SUBNETS="--subscribe-all-subnets";;
    h)
       echo "Start a beacon node"
       echo
       echo "usage: $0 <Options> <DATADIR> <NETWORK-PORT> <HTTP-PORT>"
       echo
       echo "Options:"
       echo "   -s: pass --subscribe-all-subnets to 'lighthouse bn ...', default is not passed"
       echo "   -d: DEBUG_LEVEL, default info"
       echo "   -h: this help"
       echo
       echo "Positional arguments:"
       echo "  DATADIR       Value for --datadir parameter"
       echo "  NETWORK-PORT  Value for --enr-udp-port, --enr-tcp-port and --port"
       echo "  HTTP-PORT     Value for --http-port"
       echo "  EXECUTION-ENDPOINT     Value for --execution-endpoint"
       echo "  EXECUTION-JWT     Value for --execution-jwt"
       exit
       ;;
  esac
done

# Get positional arguments
data_dir=${@:$OPTIND+0:1}
tcp_port=${@:$OPTIND+1:1}
quic_port=${@:$OPTIND+2:1}
http_port=${@:$OPTIND+3:1}
execution_endpoint=${@:$OPTIND+4:1}
execution_jwt=${@:$OPTIND+5:1}

lighthouse_binary=lighthouse

exec $lighthouse_binary \
	--debug-level $DEBUG_LEVEL \
	bn \
	$SUBSCRIBE_ALL_SUBNETS \
	--datadir $data_dir \
	--testnet-dir $TESTNET_DIR \
	--enable-private-discovery \
  --disable-peer-scoring \
	--staking \
	--enr-address 127.0.0.1 \
	--enr-udp-port $tcp_port \
	--enr-tcp-port $tcp_port \
	--enr-quic-port $quic_port \
	--port $tcp_port \
	--quic-port $quic_port \
	--http-port $http_port \
	--disable-packet-filter \
	--target-peers $((BN_COUNT - 1)) \
  --execution-endpoint $execution_endpoint \
  --execution-jwt $execution_jwt \
  --http-allow-sync-stalled \
  $BN_ARGS
