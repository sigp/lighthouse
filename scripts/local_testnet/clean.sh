#!/bin/bash

#
# Deletes all files associated with the local testnet.
#

source ./vars.env

rm -r $BEACON_DIR
rm -r $TESTNET_DIR

# Validators are slow to generate, only delete if 100% necessary.

read -p "Remove validators? (y/n)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
	rm -r $VALIDATORS_DIR
	rm -r $SECRETS_DIR
fi
