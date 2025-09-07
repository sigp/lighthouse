# Slashing Protection Interchange Tests (EIP-3076)

Tests for EIP-3076:

https://eips.ethereum.org/EIPS/eip-3076

Discussion:

https://ethereum-magicians.org/t/eip-3076-validator-client-interchange-format-slashing-protection/4883

## How to run

Each test directory contains an interchange file and some extra data about how to test it.

For example:

```json
{
  "name": "single_validator_genesis_attestation",
  "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "steps": [
    {
      "should_succeed": true,
      "contains_slashable_data": false,
      "interchange": {
        "metadata": {
          "interchange_format_version": "5",
          "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "data": [
          {
            "pubkey": "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
            "signed_blocks": [],
            "signed_attestations": [
              {
                "source_epoch": "0",
                "target_epoch": "0"
              }
            ]
          }
        ]
      },
      "blocks": [],
      "attestations": [
        {
          "pubkey": "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
          "source_epoch": "0",
          "target_epoch": "0",
          "should_succeed": false
        }
      ]
    }
  ]
}
```

To run a test, first initialize a new (empty) slashing protection database.

Then for each entry in `steps`, import the `interchange`, process the `blocks` and `attestations`,
and continue to the next step.

Determine the test outcome according to the meanings of each of the fields,
which are as follows:

* `name: string`: the name of the test-case, informational.
* `genesis_validators_root: Root`: the genesis validators root to use when
  creating the empty slashing protection database, or to compare the import
  against.
* `steps[i].should_succeed: bool`: whether the `steps[i].interchange` given is valid and should
  be imported successfully.
* `steps[i].contains_slashable_data: bool`: whether the `steps[i].interchange` contains some
  slashable data with respect to itself or the existing contents of the database.
* `steps[i].interchange: Interchange`: slashing protection interchange data as described
  by the spec.
* `steps[i].blocks: [object]`: a list of block signings to be attempted **after**
  importing the `interchange`, detailed below.
* `steps[i].attestations: [object]`: a list of attestation signings to be attempted **after**
  importing the `interchange`, detailed below.

Each block in `blocks` is structured as:

```json
{
  "pubkey": "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
  "slot": "1",
  "signing_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "should_succeed": false,
  "should_succeed_complete": true
}
```

Your test-runner should attempt to sign a block with `signing_root` at the given slot from the given
`pubkey`. The `should_succeed` field describes whether this signing should be accepted (true) or
rejected (false) _by a client using a minimal strategy_. Clients using a complete strategy should
instead use the `should_succeed_complete` field which allows signing to succeed in more cases. If
the block is signed successfully it should be incorporated into the slashing protection database.

Each attestation in `attestations` is structured as:

```json
{
  "pubkey": "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
  "source_epoch": "11",
  "target_epoch": "12",
  "signing_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "should_succeed": true,
  "should_succeed_complete": true
}
```

Similarly to above, your test-runner should attempt to sign an attestation with these parameters
using the given `pubkey`, and succeed based on the value of
`should_succeed`/`should_succeed_complete`.  Again, implementations that use the _complete_ strategy
should use `should_succeed_complete`. All implementations should incorporate signed attestations
into the database.

Note that the top-level `genesis_validators_root` is not necessarily the same
as the GVR contained in the interchange, to allow us to test the case where
they are mismatched.

## Handling Slashable Data

The `contains_slashable_data` parameter is to be interpreted as follows:

- If `should_succeed` is false, then `contains_slashable_data` is irrelevant
- If `contains_slashable_data` is false, then the given interchange **must** be imported
  successfully, and the given block/attestation checks must pass.
- If `contains_slashable_data` is true, then implementations have the option to do one of two
  things:
  	- Import the interchange successfully, working around the slashable data by minification
	  or some other mechanism. If the import succeeds, all checks must pass and the test
	  should continue to the next step.
	- Reject the interchange (or partially import it), in which case the block/attestation
	  checks and all future steps should be ignored.

## Downloading the tests

The `tests` directory is released as a versioned `.tar.gz` on the [Releases](https://github.com/eth-clients/slashing-protection-interchange-tests/releases) page.

Alternatively, you could use a git submodule.
