#!/usr/bin/env bash

# Get is cancun enabled for versions > 1.13.12. So we install 1.13.11.
cd ~
curl -LO https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-1.13.11-8f7eb9cc.tar.gz
tar xvf geth-linux-amd64-1.13.11-8f7eb9cc.tar.gz
cd geth-linux-amd64-1.13.11-8f7eb9cc/
cp geth ~/.cargo/bin/geth-stale # .cargo/bin to avoid permissions problems
cd ~
rm -r geth-linux-amd64-1.13.11-8f7eb9cc geth-linux-amd64-1.13.11-8f7eb9cc.tar.gz
