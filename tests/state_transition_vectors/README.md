# state_transition_vectors

This crate contains test vectors for Lighthouse state transition functions.

This crate serves two purposes:

- Outputting the test vectors to disk via `make`.
- Running the vectors against our code via `make test`.


## Outputting vectors to disk

Whilst we don't actually need to write the vectors to disk to test them, we
provide this functionality so we can generate corpra for the fuzzer and also so
they can be of use to other clients.

To create the files in `./vectors` (directory relative to this crate), run:

```bash
make
```

This will produce a directory structure that looks roughly like this:

```
vectors
└── exit
    ├── invalid_bad_signature
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_duplicate
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_exit_already_initiated
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_future_exit_epoch
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_not_active_after_exit_epoch
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_not_active_before_activation_epoch
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_too_young_by_a_lot
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_too_young_by_one_epoch
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── invalid_validator_unknown
    │   ├── block.ssz
    │   ├── error.txt
    │   └── pre.ssz
    ├── valid_genesis_epoch
    │   ├── block.ssz
    │   ├── post.ssz
    │   └── pre.ssz
    └── valid_previous_epoch
        ├── block.ssz
        ├── post.ssz
        └── pre.ssz
```
