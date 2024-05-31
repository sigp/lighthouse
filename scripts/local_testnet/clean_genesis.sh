#!/usr/bin/env bash

genesis_file=$1

# Reset the `genesis.json` config file fork times.
sed -i 's/"shanghaiTime".*$/"shanghaiTime": 0,/g' $genesis_file
sed -i 's/"cancunTime".*$/"cancunTime": 0,/g' $genesis_file
sed -i 's/"pragueTime".*$/"pragueTime": 0,/g' $genesis_file
