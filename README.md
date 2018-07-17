# Lighthouse 

[![Build Status](https://travis-ci.org/sigp/rust_beacon_chain.svg?branch=master)](https://travis-ci.org/sigp/rust_beacon_chain)

A **work-in-progress** implementation of the Ethereum beacon_chain in Rust.
It's named "lighthouse" because they are rusty beacons.

It is an implementation of the [Full PoS Casper chain
v2](https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ?view) spec and is also
largely based upon the
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain) repo.

## Usage

Presently this is proof-of-concept with p2p or any expected node functionality.
You can run the tests like this:

```
$ git clone <url>
$ cd rust_beacon_chain
$ cargo test
```

## Contact

This repo is presently authored by Paul Hauner as a Sigma Prime
project. 

Best place for discussion is probably the [ethereum/sharding
gitter](https://gitter.im/ethereum/sharding).

## TODO:

- [X] Implement state transitions up-to-par with the Python reference implementation.
- [ ] Ensure bls library is secure.
- [ ] Implement aggregate pub keys for BLS.
