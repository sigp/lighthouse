# Ethereum 2.0 Common Crates

Rust crates containing logic common across the Lighthouse project.

## Per-Crate Summary

- [`attester/`](attester/): Core logic for attesting to beacon and shard blocks.
- [`block_proposer/`](block_proposer/): Core logic for proposing beacon blocks.
- [`fork_choice/`](fork_choice/): A collection of fork-choice algorithms for
	the Beacon Chain.
- [`state_processing/`](state_processing/): Provides per-slot, per-block, and
	per-epoch state processing.
- [`types/`](types/): Defines base Ethereum 2.0 types (e.g., `BeaconBlock`,
	`BeaconState`, etc).
- [`utils/`](utils/):
    - [`bls`](utils/bls/): A wrapper for an external BLS encryption library.
    - [`boolean-bitfield`](utils/boolean-bitfield/): Provides an expandable vector
		of bools, specifically for use in Eth2.
    - [`fisher-yates-shuffle`](utils/fisher-yates-shuffle/): shuffles a list
		pseudo-randomly.
    - [`hashing`](utils/hashing/): A wrapper for external hashing libraries.
    - [`honey-badger-split`](utils/honey-badger-split/): Splits a list in `n`
		parts without giving AF about the length of the list, `n`, or anything
		else.
    - [`int-to-bytes`](utils/int-to-bytes/): Simple library which converts ints
		into byte-strings of various lengths.
	- [`slot_clock`](utils/slot_clock/): translates the system time into Beacon
	    Chain "slots". (Also provides another slot clock that's useful during
		testing.)
	- [`ssz`](utils/ssz/): an implementation of the SimpleSerialize 
	    serialization/deserialization protocol used by Eth 2.0.
	- [`ssz_derive`](utils/ssz_derive/): provides procedural macros for
		deriving SSZ `Encodable`, `Decodable`, and `TreeHash` methods.
	- [`swap_or_not_shuffle`](utils/swap_or_not_shuffle/): a list-shuffling
		method which is slow, but allows for a subset of indices to be shuffled.
	- [`test_random_derive`](utils/test_random_derive/): provides procedural
		macros for deriving the `TestRandom` trait defined in `types`.
