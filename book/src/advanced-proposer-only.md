# Advanced Proposer-Only Beacon Nodes

Lighthouse allows for more exotic setups that can minimize attack vectors by
adding redundant beacon nodes and dividing the roles of attesting and block
production between them. 

The purpose of this is to minimize attack vectors
where malicious users obtain the network identities (IP addresses) of beacon
nodes corresponding to individual validators and subsequently perform Denial Of Service
attacks on the beacon nodes when they are due to produce a block on the
network. By splitting the duties of attestation and block production across
different beacon nodes, an attacker may not know which node is the block
production node, especially if the user rotates IP addresses of the block
production beacon node in between block proposals (this is in-frequent with
networks with large validator counts).

## The Beacon Node

A Lighthouse beacon node can be configured with the `--proposer-only` flag
(i.e. `lighthouse bn --proposer-only`).
Setting a beacon node with this flag will limit its use as a beacon node for
normal activities such as performing attestations, but it will make the node
harder to identify as a potential node to attack and will also consume less
resources.

Specifically, this flag reduces the default peer count (to a safe minimal
number as maintaining peers on attestation subnets do not need to be considered), 
prevents the node from subscribing to any attestation-subnets or
sync-committees which is a primary way for attackers to de-anonymize
validators.

> Note: Beacon nodes that have set the `--proposer-only` flag should not be connected
> to validator clients unless via the `--proposer-nodes` flag. If connected as a
> normal beacon node, the validator may fail to handle its duties correctly and
> result in a loss of income.


## The Validator Client

The validator client can be given a list of HTTP API endpoints representing
beacon nodes that will be solely used for block propagation on the network, via
the CLI flag `--proposer-nodes`. These nodes can be any working beacon nodes
and do not specifically have to be proposer-only beacon nodes that have been
executed with the  `--proposer-only` (although we do recommend this flag for
these nodes for added security).

> Note: The validator client still requires at least one other beacon node to
> perform its duties and must be specified in the usual `--beacon-nodes` flag.

> Note: The validator client will attempt to get a block to propose from the
> beacon nodes specified in `--beacon-nodes` before trying `--proposer-nodes`.
> This is because the nodes subscribed to subnets have a higher chance of
> producing a more profitable block. Any block builders should therefore be
> attached to the `--beacon-nodes` and not necessarily the `--proposer-nodes`.


## Setup Overview

The intended set-up to take advantage of this mechanism is to run one (or more)
normal beacon nodes in conjunction with one (or more) proposer-only beacon
nodes. See the [Redundancy](./redundancy.md) section for more information about
setting up redundant beacon nodes. The proposer-only beacon nodes should be
setup to use a different IP address than the primary (non proposer-only) nodes.
For added security, the IP addresses of the proposer-only nodes should be
rotated occasionally such that a new IP-address is used per block proposal.

A single validator client can then connect to all of the above nodes via the
`--beacon-nodes` and `--proposer-nodes` flags. The resulting setup will allow
the validator client to perform its regular duties on the standard beacon nodes
and when the time comes to propose a block, it will send this block via the
specified proposer-only nodes.
