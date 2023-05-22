# Redundancy

[subscribe-api]: https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet

There are three places in Lighthouse where redundancy is notable:

1. ✅ GOOD: Using a redundant beacon node in `lighthouse vc --beacon-nodes`
1. ❌ NOT SUPPORTED: Using a redundant execution node in `lighthouse bn --execution-endpoint`
1. ☠️ BAD: Running redundant `lighthouse vc` instances with overlapping keypairs.

I mention (3) since it is unsafe and should not be confused with the other two
uses of redundancy. **Running the same validator keypair in more than one
validator client (Lighthouse, or otherwise) will eventually lead to slashing.**
See [Slashing Protection](./slashing-protection.md) for more information.

From this paragraph, this document will *only* refer to the first two items (1, 2). We
*never* recommend that users implement redundancy for validator keypairs.

## Redundant Beacon Nodes

The Lighthouse validator client can be configured to use multiple redundant beacon nodes.

The `lighthouse vc --beacon-nodes` flag allows one or more comma-separated values:

1. `lighthouse vc --beacon-nodes http://localhost:5052`
1. `lighthouse vc --beacon-nodes http://localhost:5052,http://192.168.1.1:5052`

In the first example, the validator client will attempt to contact
`http://localhost:5052` to perform duties. If that node is not contactable, not
synced or unable to serve the request then the validator client may fail to
perform some duty (e.g. produce a block or attest).

However, in the second example, any failure on `http://localhost:5052` will be
followed by a second attempt using `http://192.168.1.1:5052`. This
achieves *redundancy*, allowing the validator client to continue to perform its
duties as long as *at least one* of the beacon nodes is available.

There are a few interesting properties about the list of `--beacon-nodes`:

- *Ordering matters*: the validator client prefers a beacon node that is
	earlier in the list.
- *Synced is preferred*: the validator client prefers a synced beacon node over
	one that is still syncing.
- *Failure is sticky*: if a beacon node fails, it will be flagged as offline
    and won't be retried again for the rest of the slot (12 seconds). This helps prevent the impact
    of time-outs and other lengthy errors.

> Note: When supplying multiple beacon nodes the `http://localhost:5052` address must be explicitly
> provided (if it is desired). It will only be used as default if no `--beacon-nodes` flag is
> provided at all.

### Configuring a redundant Beacon Node

In our previous example, we listed `http://192.168.1.1:5052` as a redundant
node. Apart from having sufficient resources, the backup node should have the
following flags:

- `--http`: starts the HTTP API server.
- `--http-address 0.0.0.0`: this allows *any* external IP address to access the
	HTTP server (a firewall should be configured to deny unauthorized access to port
	`5052`). This is only required if your backup node is on a different host.
- `--execution-endpoint`: see [Merge Migration](./merge-migration.md).
- `--execution-jwt`: see [Merge Migration](./merge-migration.md).

For example one could use the following command to provide a backup beacon node:

```bash
lighthouse bn \
  --http \
  --http-address 0.0.0.0 \
  --execution-endpoint http://localhost:8551 \
  --execution-jwt /secrets/jwt.hex
```

Prior to v3.2.0 fallback beacon nodes also required the `--subscribe-all-subnets` and
`--import-all-attestations` flags. These flags are no longer required as the validator client will
now broadcast subscriptions to all connected beacon nodes by default. This broadcast behaviour
can be disabled using the `--disable-run-on-all` flag for `lighthouse vc`.

## Redundant execution nodes

Lighthouse previously supported redundant execution nodes for fetching data from the deposit
contract. On merged networks _this is no longer supported_. Each Lighthouse beacon node must be
configured in a 1:1 relationship with an execution node. For more information on the rationale
behind this decision please see the [Merge Migration](./merge-migration.md) documentation.

To achieve redundancy we recommend configuring [Redundant beacon nodes](#redundant-beacon-nodes)
where each has its own execution engine.
