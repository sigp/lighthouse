# Ethereum Serenity

This document aims at providing a high level understanding of Ethereum and the
Serenity phase of the Ethereum roadmap.

## The Blockchain

A blockchain can be seen as a decentralized, distributed ledger. The ledger of
transactions is replicated onto all nodes in the network. When a transaction
occurs, it is first propagated to the nodes. Once the nodes receive the
transaction, and verifies the correctness, the nodes attempt to batch the
transactions into a block and append the block to the ledger. Once the ledger
has been successfully appended onto, they propagate the block to the network.
If accepted, this block now becomes the latest block in the chain. If two people
propose a block at the same time, the one canonical blockchain forks. At this
point it must be resolved, and each system has it's own way of resolving these
forks.

![Blockchain](http://yuml.me/b0d6b30a.jpg)
<center>Figure 1. Example blockchain with a resolved fork.</center>

<br>

The idea of the blockchain was first proposed in the seminal [Bitcoin
whitepaper](https://bitcoin.org/bitcoin.pdf) by Satoshi Nakamoto. Since then, a
vast number of updates and blockchains have taken shape providing different
functionality or properties to the original blockchain.

## What is Ethereum?

Ethereum is an open blockchain protocol, allowing for the building and use of
decentralized applications that run on blockchain technology. Ethereum was one
of the initial platforms providing turing-complete code to be run on the
blockchain, allowing for conditional payments to occur through the use of this
code. Since then, Ethereum has advanced to allow for a number of Decentralized
Applications (DApps) to be developed and run completely with the blockchain as
the backbone.

General Ethereum Introduction:

* [What is Ethereum](http://ethdocs.org/en/latest/introduction/what-is-ethereum.html)
* [Ethereum Introduction](https://github.com/ethereum/wiki/wiki/Ethereum-introduction)


### Proof-of-Work and the current state of Ethereum.

Currently, Ethereum is based on the Proof-of-Work model, a Sybil resilient
mechanism to allow nodes to propose blocks to the network. Although it provides
properties that allow the blockchain to operate in an open, public
(permissionless) network, it faces it's challenges and as a result impacts
the operation of the blockchain.

The main goals to advance Ethereum is to (1) increase the scalability and
overall transaction processing power of the Ethereum world computer and (2)
find a suitable replacement for Proof-of-Work that still provides the necessary
properties that we need.

* [Proof-of-Work in Cryptocurrencies: an accessible introduction](https://blog.sigmaprime.io/what-is-proof-of-work.html)

## Serenity

Ethereum Serenity refers to a new blockchain system currently under development
by the Ethereum Foundation and the Ethereum community.

As part of the original Ethereum roadmap
[\[1\]](https://blog.ethereum.org/2015/03/03/ethereum-launch-process/)
[\[2\]](http://ethdocs.org/en/latest/introduction/the-homestead-release.html),
the Proof-of-Stake integration falls under **Release Step 4: *Serenity***. With
this, a number of changes are to be made to the current Ethereum protocol to
incorporate some of the new Proof-of-Stake mechanisms as well as improve on
some of the hindrances faced by the current Proof-of-Work chain.

To now advance the current Ethereum, the decision is made to move to a sharded
Beacon chain structure where multiple shard-chains will be operating and
interacting with a central beacon chain.The Serenity blockchain consists of
1,025 proof-of-stake blockchains. This includes the "beacon chain" and 1,024
"shard chains".

Ethereum Serenity is also known as "Ethereum 2.0" and "Shasper". We prefer
Serenity as it more accurately reflects the established Ethereum roadmap (plus
we think it's a nice name).

(Be mindful, the specifications change occasionally, so check these to keep up
to date)

* Current Specifications:
  * [Danny Ryan's "State of the Spec"](https://notes.ethereum.org/s/BJEZWNoyE) (A nice summary of the current specifications)
  * [Ethereum Serenity - Phase 0: Beacon Chain Spec](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md)
  * [Ethereum Serenity - Phase 1: Sharded Data Chains](https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/1_shard-data-chains.md)
  * [Beacon Chain - Vitalik Buterin and Justin Drake explain](https://www.youtube.com/watch?v=GAywmwGToUI)
* Understanding Sharding:
  * [Prysmatic Labs: Sharding Explained](https://medium.com/prysmatic-labs/how-to-scale-ethereum-sharding-explained-ba2e283b7fce)
* Other relevant resources
  * [Proof of Stake - Casper FFG](https://www.youtube.com/watch?v=uQ3IqLDf-oo)
  * [Justin Drake VDF Devcon4 Talk](https://www.youtube.com/watch?v=zqL_cMlPjOI)


### Beacon Chain

The concept of a beacon chain differs from existing blockchains, such as
Bitcoin and Ethereum, in that it doesn't process transactions per se. Instead,
it maintains a set of bonded (staked) validators and coordinates these to
provide services to a static set of *sub-blockchains* (i.e. shards). Each of
these shard blockchains processes normal transactions (e.g. "Transfer 5 ETH
from A to B") in parallel whilst deferring consensus mechanisms to the beacon
chain.

Major services provided by the beacon chain to its shards include the following:

- A source of entropy, likely using a [RANDAO + VDF
  scheme](https://ethresear.ch/t/minimal-vdf-randomness-beacon/3566).
- Validator management, including:
    - Inducting and ejecting validators.
    - Assigning randomly-shuffled subsets of validators to particular shards.
    - Penalizing and rewarding validators.
- Proof-of-stake consensus for shard chain blocks.

### Shard Chains

Shards are analogous to CPU cores - they're a resource where transactions can
execute in series (one-after-another). Presently, Ethereum is single-core and
can only _fully_ process one transaction at a time. Sharding allows processing
of multiple transactions simultaneously, greatly increasing the per-second
transaction capacity of Ethereum.

Each shard uses a proof-of-stake consensus mechanism and shares its validators
(stakers) with other shards. The beacon chain rotates validators
pseudo-randomly between different shards.  Shards will likely be the basis of
layer-2 transaction processing schemes, however, that is not in scope of this
discussion.

### The Proof-of-Work Chain

The present-Ethereum proof-of-work (PoW) chain will host a smart contract that
enables accounts to deposit 32 ETH, a BLS public key, and some [other
parameters](https://github.com/ethereum/eth2.0-specs/blob/master/specs/casper_sharding_v2.1.md#pow-chain-changes),
allowing them to become beacon chain validators. Each beacon chain will
reference a PoW block hash allowing PoW clients to use the beacon chain as a
source of [Casper FFG finality](https://arxiv.org/abs/1710.09437), if desired.

It is a requirement that ETH can move freely between shard chains, as well as between
Serenity and present-Ethereum blockchains. The exact mechanics of these transfers remain
an active topic of research and their details are yet to be confirmed.

## Serenity Progress

Ethereum Serenity is not fully specified and a working implementation does not
yet exist. Some teams have demos available which indicate progress, but do not
constitute a complete product.  We look forward to providing user functionality
once we are ready to provide a minimum-viable user experience.

The work-in-progress specifications live in the
[ethereum/eth2.0-specs](https://github.com/ethereum/eth2.0-specs) repository.
There is active discussion about the specification in the
[ethereum/sharding](https://gitter.im/ethereum/sharding) gitter channel. A
proof-of-concept implementation in Python is available at
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain).

Presently, the specification focuses almost exclusively on the beacon chain,
as it is the focus of current development efforts. Progress on shard chain
specification will soon follow.
