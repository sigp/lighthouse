#!/usr/bin/env bash

priv_key="02fd74636e96a8ffac8e7b01b0de8dea94d6bcf4989513b38cf59eb32163ff91"
source ./vars.env
exec $EL_BOOTNODE_BINARY --nodekeyhex $priv_key
