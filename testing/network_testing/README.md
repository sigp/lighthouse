# Lighthouse live network testing


## DISCLAIMER

This document describes how to run a lighthouse node with minimal resources and time on a live
network.

This procedure should ONLY be used for testing networks and never in production and never with
attached validators. The Lighthouse node described in this state is only a partially functioning
node.


## Overview

We are going to run a single lighthouse node connected to a live network, without syncing and
without an execution engine. This should only ever be done for testing.

There two main components needed.

1. A lighthouse node that doesn't sync
2. A fake execution client that does nothing

We will start with the second

## Mock-EL

This is a service that runs and fakes an execution engine. We firstly need to install the lighthouse
`lcli` tool.

```
$ make install-lcli
```

Once installed, run the fake execution client:

```
$ lcli mock-el --jwt-output-path /tmp/mockel.jwt
```

This will create a server listening on localhost:8551

## Lighthouse no sync

To create a lighthouse node that doesn't sync we need to compile it with a special flag.

```
$ cargo build --release --bin lighthouse --features network/disable-backfill
```

Once built, it can run via checkpoint sync on any network, making sure we point to our mock-el

Holesky testnet:

```
$ lighthouse --network holesky bn --execution-jwt /tmp/mockel.jwt --checkpoint-sync-url
https://holesky.checkpoint.sigp.io --execution-endpoint http://localhost:8551
```

Mainnet:

```
$ lighthouse --network mainnet bn --execution-jwt /tmp/mockel.jwt --checkpoint-sync-url
https://checkpoint.sigp.io --execution-endpoint http://localhost:8551
```

Additional flags, such as metrics may be added.


## Additional Notes

The above is assuming that you have not run the command in the past. If you have a database in
existence for the network you are testing, checkpoint sync will not start. You may need to add the
`--purge-db` flag to remove any past database and force checkpoint sync to run.
