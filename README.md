# Rust Beacon Chain 

[![Build Status](https://travis-ci.org/sigp/rust_beacon_chain.svg?branch=master)](https://travis-ci.org/sigp/rust_beacon_chain)

A **work-in-progress** implementation of the Ethereum beacon_chain in Rust.

It is an implementation of the [Full PoS Casper chain
v2](https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ?view) spec and is also
largely based upon the
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain) repo.

## Usage

Presently this is just a bunch of data structures and some tests.

```
$ git clone <url>
$ cd rust_beacon_chain
$ cargo test
```

## Contact

This repo is presently authored by Paul Hauner (@paulhauner) as a Sigma Prime
project. 

Best place for discussion is probably the [ethereum/sharding
gitter](https://gitter.im/ethereum/sharding).

## TODO:

- [ ] Finish state transition implementation.
- [ ] Ensure bls library is secure.
- [ ] Implement RLP serialization for BLS signatures.
