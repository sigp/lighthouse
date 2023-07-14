# Database Configuration

Lighthouse uses an efficient "split" database schema, whereby finalized states are stored separately
from recent, unfinalized states. We refer to the portion of the database storing finalized states as
the _freezer_ or _cold DB_, and the portion storing recent states as the _hot DB_.

In both the hot and cold DBs, full `BeaconState` data structures are only stored periodically, and
intermediate states are reconstructed by quickly replaying blocks on top of the nearest state. For
example, to fetch a state at slot 7 the database might fetch a full state from slot 0, and replay
blocks from slots 1-7 while omitting redundant signature checks and Merkle root calculations. The
full states upon which blocks are replayed are referred to as _restore points_ in the case of the
freezer DB, and _epoch boundary states_ in the case of the hot DB.

The frequency at which the hot database stores full `BeaconState`s is fixed to one-state-per-epoch
in order to keep loads of recent states performant. For the freezer DB, the frequency is
configurable via the `--slots-per-restore-point` CLI flag, which is the topic of the next section.

## Freezer DB Space-time Trade-offs

Frequent restore points use more disk space but accelerate the loading of historical states.
Conversely, infrequent restore points use much less space, but cause the loading of historical
states to slow down dramatically. A lower _slots per restore point_ value (SPRP) corresponds to more
frequent restore points, while a higher SPRP corresponds to less frequent. The table below shows
some example values.

| Use Case                   | SPRP | Yearly Disk Usage* | Load Historical State |
|----------------------------|------|-------------------|-----------------------|
| Research                   | 32   | 3.4 TB            | 155 ms                |
| Block explorer/analysis    | 128  | 851 GB            | 620 ms                |
| Enthusiast (prev. default) | 2048 | 53.6 GB           | 10.2 s                |
| Hobbyist                  | 4096 | 26.8 GB           | 20.5 s                |
| Validator only (default)   | 8192 | 8.1 GB            | 41 s                  |

*Last update: May 2023. 

As we can see, it's a high-stakes trade-off! The relationships to disk usage and historical state
load time are both linear – doubling SPRP halves disk usage and doubles load time. The minimum SPRP
is 32, and the maximum is 8192.

The default value is 8192 for databases synced from scratch using Lighthouse v2.2.0 or later, or
2048 for prior versions. Please see the section on [Defaults](#defaults) below.

The values shown in the table are approximate, calculated using a simple heuristic: each
`BeaconState` consumes around 18MB of disk space, and each block replayed takes around 5ms.  The
**Yearly Disk Usage** column shows the approximate size of the freezer DB _alone_ (hot DB not included), calculated proportionally using the total freezer database disk usage. 
The **Load Historical State** time is the worst-case load time for a state in the last slot
before a restore point. 

As an example, we use an SPRP of 4096 to calculate the total size of the freezer database until May 2023. It has been about 900 days since the genesis, the total disk usage by the freezer database is therefore: 900/365*26.8 GB = 66 GB. 

### Defaults

As of Lighthouse v2.2.0, the default slots-per-restore-point value has been increased from 2048
to 8192 in order to conserve disk space. Existing nodes will continue to use SPRP=2048 unless
re-synced. Note that it is currently not possible to change the SPRP without re-syncing, although
fast re-syncing may be achieved with [Checkpoint Sync](./checkpoint-sync.md).

### CLI Configuration

To configure your Lighthouse node's database with a non-default SPRP, run your Beacon Node with
the `--slots-per-restore-point` flag:

```bash
lighthouse beacon_node --slots-per-restore-point 32
```

### Historic state cache

Lighthouse includes a cache to avoid repeatedly replaying blocks when loading historic states. Lighthouse will cache a limited number of reconstructed states and will re-use them when serving requests for subsequent states at higher slots. This greatly reduces the cost of requesting several states in order, and we recommend that applications like block explorers take advantage of this cache.

The historical state cache size can be specified with the flag `--historic-state-cache-size` (default value is 1):

```bash
lighthouse beacon_node --historic-state-cache-size 4
```

> Note: This feature will cause high memory usage.

## Glossary

* _Freezer DB_: part of the database storing finalized states. States are stored in a sparser
  format, and usually less frequently than in the hot DB.
* _Cold DB_: see _Freezer DB_.
* _Hot DB_: part of the database storing recent states, all blocks, and other runtime data. Full
  states are stored every epoch.
* _Restore Point_: a full `BeaconState` stored periodically in the freezer DB.
* _Slots Per Restore Point (SPRP)_: the number of slots between restore points in the freezer DB.
* _Split Slot_: the slot at which states are divided between the hot and the cold DBs. All states
  from slots less than the split slot are in the freezer, while all states with slots greater than
  or equal to the split slot are in the hot DB.
