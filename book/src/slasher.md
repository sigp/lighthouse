# Running a Slasher

Lighthouse includes a slasher for identifying slashable offences comitted by other validators and
including proof of those offences in blocks.

Running a slasher is a good way to contribute to the health of the network, and doing so can earn
extra income for your validators. However it is currently only recommended for expert users because
of the immaturity of the slasher UX and the extra resources required.

## Minimum System Requirements

* Quad-core CPU
* 16 GB RAM
* 256 GB solid state storage (in addition to space for the beacon node DB)
* ⚠️ **If you are running natively on Windows**: LMDB will pre-allocate the entire 256 GB for the slasher database

## How to Run

The slasher runs inside the same process as the beacon node, when enabled via the `--slasher` flag:

```
lighthouse bn --slasher --debug-level debug
```

The slasher hooks into Lighthouse's block and attestation processing, and pushes messages into an
in-memory queue for regular processing. It will increase the CPU usage of the beacon node because it
verifies the signatures of otherwise invalid messages. When a slasher batch update runs, the
messages are filtered for relevancy, and all relevant messages are checked for slashings and written
to the slasher database.

You **should** run with debug logs, so that you can see the slasher's internal machinations, and
provide logs to the devs should you encounter any bugs.

## Configuration

The slasher has several configuration options that control its functioning.

### Database Directory

* Flag: `--slasher-dir PATH`
* Argument: path to directory

By default the slasher stores data in the `slasher_db` directory inside the beacon node's datadir,
e.g. `~/.lighthouse/{network}/beacon/slasher_db`. You can use this flag to change that storage
directory.

### History Length

* Flag: `--slasher-history-length EPOCHS`
* Argument: number of epochs
* Default: 4096 epochs

The slasher stores data for the `history-length` most recent epochs. By default the history length
is set high in order to catch all validator misbehaviour since the last weak subjectivity
checkpoint. If you would like to reduce the resource requirements (particularly disk space), set the
history length to a lower value, although a lower history length may prevent your slasher from
finding some slashings.

**Note:** See the `--slasher-max-db-size` section below to ensure that your disk space savings are
applied. The history length must be a multiple of the chunk size (default 16), and cannot be
changed after initialization.

### Max Database Size

* Flag: `--slasher-max-db-size GIGABYTES`
* Argument: maximum size of the database in gigabytes
* Default: 256 GB

The slasher uses LMDB as its backing store, and LMDB will consume up to the maximum amount of disk
space allocated to it. By default the limit is set to accomodate the default history length and
around 150K validators but you can set it lower if running with a reduced history length. The space
required scales approximately linearly in validator count and history length, i.e. if you halve
either you can halve the space required.

If you want a better estimate you can use this formula:

```
360 * V * N + (16 * V * N)/(C * K) + 15000 * N
```

where

* `V` is the validator count
* `N` is the history length
* `C` is the chunk size
* `K` is the validator chunk size

### Update Period

* Flag: `--slasher-update-period SECONDS`
* Argument: number of seconds
* Default: 12 seconds

Set the length of the time interval between each slasher batch update. You can check if your
slasher is keeping up with its update period by looking for a log message like this:

```
DEBG Completed slasher update num_blocks: 1, num_attestations: 279, time_taken: 1821ms, epoch: 20889, service: slasher
```

If the `time_taken` is substantially longer than the update period then it indicates your machine is
struggling under the load, and you should consider increasing the update period or lowering the
resource requirements by tweaking the history length.

### Chunk Size and Validator Chunk Size

* Flags: `--slasher-chunk-size EPOCHS`, `--slasher-validator-chunk-size NUM_VALIDATORS`
* Arguments: number of ecochs, number of validators
* Defaults: 16, 256

Adjusting these parameter should only be done in conjunction with reading in detail
about [how the slasher works][design-notes], and/or reading the source code.

[design-notes]: https://hackmd.io/@sproul/min-max-slasher

### Short-Range Example

If you would like to run a lightweight slasher that just checks blocks and attestations within
the last day or so, you can use this combination of arguments:

```
lighthouse bn --slasher --slasher-history-length 256 --slasher-max-db-size 16 --debug-level debug
```

## Stability Warning

The slasher code is still quite new, so we may update the schema of the slasher database in a
backwards-incompatible way which will require re-initialization.
