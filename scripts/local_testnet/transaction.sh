#!/bin/bash
# Define the node endpoint
NODE_ENDPOINT="http://localhost:6005"

# Import the private key
geth --jspath "./" --exec 'loadScript("transaction.js")' attach $NODE_ENDPOINT
