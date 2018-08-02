# Lighthouse: a (future) Ethereum 2.0 client 

[![Build Status](https://travis-ci.org/sigp/lighthouse.svg?branch=master)](https://travis-ci.org/sigp/lighthouse)

A **work-in-progress** implementation of the Ethereum 2.0 Beacon Chain in Rust.

It is an implementation of the [Full PoS Casper chain
v2](https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ?view) spec and is also
largely based upon the
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain) repo.

**NOTE: the cryptography libraries used in this implementation are very
experimental and as such all cryptography should be assumed to be insecure.**

## Motivation

The objective of this project is to build a purely Ethereum 2.0 client from
the ground up.

As such, the early days of Lighthouse will be very much a research effort -- it
will be evolving on the bleeding-edge of specification without requiring to
maintain prod-grade stability or backwards-compatibility for the existing PoW
chain. 

Whilst the Beacon Chain relies upon the PoW chain for block hashes, Lighthouse
will need to run alongside an existing client (e.g., Geth, Parity Ethereum),
only being able to stand by itself once the PoW chain has been deprecated.

Lighthouse aims to assist in advancing the progress of the following Ethereum
technologies:

 - Proof-of-Stake
 - Sharding
 - EVM alternatives (e.g., WASM)
 - Scalable, topic-based P2P networks (e.g., libp2p-gossipsub) 
 - Scalable signature schemes (e.g, BLS aggregates)

## Progress

As of 02/08/2018, there is a basic libp2p implementation alongside a series of
state objects and state transition functions. There are no syncing capabilities.

### Roadmap

 - [ ] Upgrade to the v2.1 spec.
 - [ ] Implement local storage (e.g., RocksDB, LevelDB).
 - [ ] Implement a syncing procedure.
 - [ ] Align to whichever P2P spec is chosen for the Beacon Chain by the EF.
 - [ ] Provide validation services (participate in consensus)

## Usage

You can run the tests like this:

```
$ git clone <url>
$ cd rust_beacon_chain
$ cargo test
```

## Contact

This repo is presently authored by Paul Hauner as a 
[Sigma Prime](https://github.com/sigp) project. 

The best place for discussion is probably the [ethereum/sharding
gitter](https://gitter.im/ethereum/sharding).
