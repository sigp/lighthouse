#!/usr/bin/env bash

#
# Deletes all files associated with the local testnet.
#

set -Eeuo pipefail

source ./vars.env

if [ -d $DATADIR ]; then
  rm -rf $DATADIR
fi
