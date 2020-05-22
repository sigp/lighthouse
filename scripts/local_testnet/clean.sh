#!/bin/bash

#
# Deletes all files associated with the local testnet.
#

source ./vars.env

rm -r $DATADIR
