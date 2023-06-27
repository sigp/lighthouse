# Running a Slasher

Lighthouse includes a slasher for identifying slashable offences committed by other validators and
including proof of those offences in blocks.

Running a slasher is a good way to contribute to the health of the network, and doing so can earn
extra income for your validators. However it is currently only recommended for expert users because
of the immaturity of the slasher UX and the extra resources required.

## Minimum System Requirements
* Quad-core CPU
* 16 GB RAM
* 256 GB solid state storage (in addition to the space requirement for the beacon node DB)

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
provide logs to the developers should you encounter any bugs.

## Configuration

The slasher has several configuration options that control its functioning.

### Database Directory

* Flag: `--slasher-dir PATH`
* Argument: path to directory

By default the slasher stores data in the `slasher_db` directory inside the beacon node's datadir,
e.g. `~/.lighthouse/{network}/beacon/slasher_db`. You can use this flag to change that storage
directory.

### Database Backend

* Flag: `--slasher-backend NAME`
* Argument: one of `mdbx`, `lmdb` or `disabled`
* Default: `lmdb` for new installs, `mdbx` if an MDBX database already exists

It is possible to use one of several database backends with the slasher:

- LMDB (default)
- MDBX

The advantage of MDBX is that it performs compaction, resulting in less disk usage over time. The
disadvantage is that upstream MDBX is unstable, so Lighthouse is pinned to a specific version.
If bugs are found in our pinned version of MDBX it may be deprecated in future.

LMDB does not have compaction but is more stable upstream than MDBX. If running with the LMDB
backend on Windows it is recommended to allow extra space due to this issue:
[sigp/lighthouse#2342](https://github.com/sigp/lighthouse/issues/2342).

More backends may be added in future.

#### Backend Override

The default backend was changed from MDBX to LMDB in Lighthouse v4.3.0.

If an MDBX database is already found on disk, then Lighthouse will try to use it. This will result
in a log at start-up:

```
INFO Slasher backend overriden    reason: database exists, configured_backend: lmdb, overriden_backend: mdbx
```

If the running Lighthouse binary doesn't have the MDBX backend enabled but an existing database is
found, then a warning will be logged and Lighthouse will use the LMDB backend and create a new database:

```
WARN Slasher backend override failed    advice: delete old MDBX database or enable MDBX backend, path: /home/user/.lighthouse/mainnet/beacon/slasher_db/mdbx.dat
```

In this case you should either obtain a Lighthouse binary with the MDBX backend enabled, or delete
the files for the old backend. The pre-built Lighthouse binaries and Docker images have MDBX enabled,
or if you're [building from source](./installation-source.md) you can enable the `slasher-mdbx` feature.

To delete the files, use the `path` from the `WARN` log, and then delete the `mbdx.dat` and
`mdbx.lck` files.

#### Switching Backends

If you change database backends and want to reclaim the space used by the old backend you can
delete the following files from your `slasher_db` directory:

* removing MDBX: delete `mdbx.dat` and `mdbx.lck`
* removing LMDB: delete `data.mdb` and `lock.mdb`

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

Both database backends LMDB and MDBX place a hard limit on the size of the database
file. You can use the `--slasher-max-db-size` flag to set this limit. It can be adjusted after
initialization if the limit is reached.

By default the limit is set to accommodate the default history length and around 600K validators (with about 30% headroom) but
you can set it lower if running with a reduced history length. The space required scales
approximately linearly in validator count and history length, i.e. if you halve either you can halve
the space required.

If you want an estimate of the database size you can use this formula:

```
4.56 GB * (N / 256) * (V / 250000)
```

where `N` is the history length and `V` is the validator count.

You should set the maximum size higher than the estimate to allow room for growth in the validator
count.

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

The update period should almost always be set to a multiple of the slot duration (12
seconds), or in rare cases a divisor (e.g. 4 seconds).

### Slot Offset

* Flag: `--slasher-slot-offset SECONDS`
* Argument: number of seconds (decimal allowed)
* Default: 10.5 seconds

Set the offset from the start of the slot at which slasher processing should run. The default
value of 10.5 seconds is chosen so that de-duplication can be maximally effective. The slasher
will de-duplicate attestations from the same batch by storing only the attestations necessary
to cover all seen validators. In other words, it will store aggregated attestations rather than
unaggregated attestations if given the opportunity.

Aggregated attestations are published 8 seconds into the slot, so the default allows 2.5 seconds for
them to arrive, and 1.5 seconds for them to be processed before a potential block proposal at the
start of the next slot. If the batch processing time on your machine is significantly longer than
1.5 seconds then you may want to lengthen the update period to 24 seconds, or decrease the slot
offset to a value in the range 8.5-10.5s (lower values may result in more data being stored).

The slasher will run every `update-period` seconds after the first `slot_start + slot-offset`, which
means the `slot-offset` will be ineffective if the `update-period` is not a multiple (or divisor) of
the slot duration.

### Chunk Size and Validator Chunk Size

* Flags: `--slasher-chunk-size EPOCHS`, `--slasher-validator-chunk-size NUM_VALIDATORS`
* Arguments: number of epochs, number of validators
* Defaults: 16, 256

Adjusting these parameter should only be done in conjunction with reading in detail
about [how the slasher works][design-notes], and/or reading the source code.

[design-notes]: https://hackmd.io/@sproul/min-max-slasher

### Attestation Root Cache Size

* Flag: `--slasher-att-cache-size COUNT`
* Argument: number of attestations
* Default: 100,000

The number of attestation data roots to cache in memory. The cache is an LRU cache used to map
indexed attestation IDs to the tree hash roots of their attestation data. The cache prevents reading
whole indexed attestations from disk to determine whether they are slashable.

Each value is very small (38 bytes) so the entire cache should fit in around 4 MB of RAM. Decreasing
the cache size is not recommended, and the size is set so as to be large enough for future growth.

### Short-Range Example

If you would like to run a lightweight slasher that just checks blocks and attestations within
the last day or so, you can use this combination of arguments:

```
lighthouse bn --slasher --slasher-history-length 256 --slasher-max-db-size 16 --debug-level debug
```

## Stability Warning

The slasher code is still quite new, so we may update the schema of the slasher database in a
backwards-incompatible way which will require re-initialization.
