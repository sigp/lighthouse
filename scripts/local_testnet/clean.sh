#!/bin/bash

#
# Deletes all files associated with the local testnet.
#

source ./vars.env

if [ -d $DATADIR ]; then
  rm -r $DATADIR
fi
