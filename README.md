# rust_beacon_chain

A *work-in-progress* implementation of the Ethereum beacon_chain in Rust.

It is an implementation of [this
spec](https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ?view) and is also
largely based upon the
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain) repo.

## Usage

Presently this is just a bunch of data structures and some tests.

```
$ git clone --recurse-submodules <url>
$ cd rust_beacon_chain
$ cargo test
```

_Note: don't forget to clone/pull with respect to submodules. Parity is
included as a submodule so we can use their handy RLP module without compiling
all the things._

## Contact

This repo is presently authored by Paul Hauner (@paulhauner) as a Sigma Prime
project. 

Best place for discussion is probably the [ethereum/sharding
gitter](https://gitter.im/ethereum/sharding).

## TODO:

- [] Implement crystallized state.
- [] Implement state transition.
- [] Implement integration tests (some unit tests are implemented now).
- [] Implement RLP serialization across-the-board.
- [] Ensure bls library is legit (i.e., functioning and secure).
- [] Implement the things, optimise them & scale to 1000000000 nodes.
