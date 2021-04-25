# Redundancy

[subscribe-api]: https://ethereum.github.io/eth2.0-APIs/#/Validator/prepareBeaconCommitteeSubnet

There are three places in Lighthouse where redundancy is notable:

1. ✅ GOOD: Using a redundant Beacon node in `lighthouse vc --beacon-nodes`
1. ✅ GOOD: Using a redundant Eth1 node in `lighthouse bn --eth1-endpoints`
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
    and wont be retried again for the rest of the slot (12 seconds). This helps prevent the impact
    of time-outs and other lengthy errors.

> Note: When supplying multiple beacon nodes the `http://localhost:5052` address must be explicitly
> provided (if it is desired). It will only be used as default if no `--beacon-nodes` flag is
> provided at all.

### Configuring a redundant Beacon Node

In our previous example we listed `http://192.168.1.1:5052` as a redundant
node. Apart from having sufficient resources, the backup node should have the
following flags:

- `--staking`: starts the HTTP API server and ensures the Eth1 chain is synced.
- `--http-address 0.0.0.0`: this allows *any* external IP address to access the
	HTTP server (a firewall should be configured to deny unauthorized access to port
	`5052`). This is only required if your backup node is on a different host.
- `--subscribe-all-subnets`: ensures that the beacon node subscribes to *all*
	subnets, not just on-demand requests from validators.
- `--process-all-attestations`: ensures that the beacon node performs
	aggregation on all seen attestations.

Subsequently, one could use the following command to provide a backup beacon
node:

```bash
lighthouse bn \
  --staking \
  --http-address 0.0.0.0 \
  --subscribe-all-subnets \
  --process-all-attestations
```

### Resource usage of redundant Beacon Nodes

The `--subscribe-all-subnets` and `--process-all-attestations` flags typically
cause a significant increase in resource consumption. A doubling in CPU
utilization and RAM consumption is expected.

The increase in resource consumption is due to the fact that the beacon node is
now processing, validating, aggregating and forwarding *all* attestations,
whereas previously it was likely only doing a fraction of this work. Without
these flags, subscription to attestation subnets and aggregation of
attestations is only performed for validators which [explicitly request
subscriptions](subscribe-api).

There are 64 subnets and each validator will result in a subscription to *at
least* one subnet. So, using the two aforementioned flags will result in
resource consumption akin to running 64+ validators.

## Redundant Eth1 nodes

Compared to redundancy in beacon nodes (see above), using redundant Eth1 nodes
is very straight-forward:

1. `lighthouse bn --eth1-endpoints http://localhost:8545`
1. `lighthouse bn --eth1-endpoints http://localhost:8545,http://192.168.0.1:8545`

In the case of (1), any failure on `http://localhost:8545` will result in a
failure to update the Eth1 cache in the beacon node. Consistent failure over a
period of hours may result in a failure in block production.

However, in the case of (2), the `http://192.168.0.1:8545` Eth1 endpoint will
be tried each time the first fails. Eth1 endpoints will be tried from first to
last in the list, until a successful response is obtained.

There is no need for special configuration on the Eth1 endpoint, all endpoints can (probably should)
be configured identically.

> Note: When supplying multiple endpoints the `http://localhost:8545` address must be explicitly
> provided (if it is desired). It will only be used as default if no `--eth1-endpoints` flag is
> provided at all.
