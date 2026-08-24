# tree-sync

Sync by root. Walk back by `parent_root` to a known block, import forward. No `*_by_range`. Peers are adversarial.

## Constants

`B = 32` roots promoted at a time (protocol cap 128)
`N = 256` max blocks forward syncing — 8 chains in flight
`RETRY_MAX = 5`
`ROOTS_MAX = 1_000_000` tracked roots before pruning

## State

```
FC        : Set<Root>                 -- fork choice; external, grows only
finalized : (Root, Slot)              -- external, grows only
loc       : Root ⇀ ChainId
chains    : ChainId ⇀ Chain
owners(R) = [ loc(r) | r ∈ R, loc(r) defined ], deduped, ascending by min slot

Chain =
  | Backfill    { roots, peers, errors: Nat, state: Discovering(Root) | Anchored(Root) }
  | ForwardSync { roots, peers, parent: Root, errors: Nat
                , state: Downloading | Ready(Seq<Block>) | Processing(Seq<Block>) }

roots : Seq<(Root, Slot)>   -- tip first
peers : Set<Peer>           -- hold ALL of roots
```

Init: all empty. `peers` is live, not captured: an in-flight call uses a peer added mid-flight, no retry. Column fetches stall on custody peers. Hence `Search`'s eager admission and the ascent.

## Operations

```
Split(c, r) = (Y, Z)      guard r ∈ c.roots ∧ r ≠ c.roots[0]
  c.roots = [tip … r⁺] ++ [r … oldest]
  Z = { roots: [tip … r⁺],   peers: c.peers }      -- Z.parent = Y.roots[0]
  Y = { roots: [r … oldest], peers: c.peers }      -- Y.parent = c.parent

  Backfill      Y.state := c.state     Z.state := Anchored(r)
  ForwardSync   Y.state := c.state↾Y   Z.state := c.state↾Z
  both inherit c.errors

  x↾c = x with its blocks restricted to those whose root ∈ c.roots

Merge(Y, Z) = c           guard Z.state = Anchored(Y.roots[0]) ∧ Y.peers = Z.peers
  c = { roots: Z.roots ++ Y.roots, peers: Y.peers, state: Y.state }
```

`Y ⊎ Z = c`. `Merge(Split(c, r)) = c` for `Backfill`. Callers own `loc`. No transition invokes `Merge`; it is a background compaction. Both halves keep awaiting the shared in-flight call: `OnDownload` and `OnProcess` dispatch its result per root via `loc`.

## Transitions

**`Search(r, P)`** — from peer `STATUS.head_root`, gossip unknown `parent_root`, or attested root.
- `r ∈ FC` ∨ `slot(r) ≤ slot(finalized)` → skip
- `loc(r)` undefined → new `Backfill{roots:[], peers:P, errors:0}`; `loc(r) :=` it; `SendHeaders(c, r)`
- `loc(r) = c`, `r = c.roots[0]` → `c.peers ∪= P`
- `loc(r) = c` → `(Y,Z) := Split(c,r)`; `Y.peers ∪= P`; `loc[Z.roots] := Z`

then ascend: add `P` to every chain holding an ancestor of `r`, following `parent` links to `FC`.

**`SendHeaders(c, root)`** — `c.state := Discovering(root)`, served from `c.peers`. Guarantees `OnHeaders(c, result)`, where `Ok(h)` has `h[0].root = root` ∧ `h[i].root = h[i−1].parent_root` ∧ `h[i].slot < h[i−1].slot`.

**`OnHeaders(c, result)`** — guard `c.state = Discovering(next)`.
- `Err` → `errors += 1`; `errors > RETRY_MAX` → `Drop(c)`, else `SendHeaders(c, next)`
- `Ok(headers)`, for `header ∈ headers`:
  - `header.slot ≤ slot(finalized) ∧ header.root ≠ root(finalized)` → `report_peer(c.peers)`; `Drop(c)`
  - push `(header.root, header.slot)`; `p := header.parent_root`
  - `p ∈ FC` ∨ `loc(p)` defined → `state := Anchored(p)`; halt
  - else → `loc(p) := c`; `SendHeaders(c, p)`; continue

**`Promote`** — runs after every transition.
- every `Ready(blocks)` with `c.parent ∈ FC` → `SendProcess(c)`
- while `syncing_blocks < N`; `syncing_blocks = Σ |c.roots|` over `ForwardSync` chains:
- pick `c` = `Backfill{state: Anchored(parent)}` and `parent ∈ FC ∨ loc(parent) is ForwardSync`
- `(Y,Z) := Split(c, `the `B`th-oldest root`)`
- `Y` → `ForwardSync{roots:Y.roots, peers:Y.peers, parent:c.parent, errors:0}`; `SendDownload(Y)`
- `Z` → `Backfill{state: Anchored(Y.roots[0])}`

**`SendDownload(c)`** — `c.state := Downloading`, served from `c.peers`. Guarantees `OnDownload(R, result)` with `R = c.roots`, where `Ok(blocks)` has `roots(blocks) = R`, each verified by root.

**`OnDownload(R, result)`** — for each `c ∈ owners(R)`:
- `Ok(blocks)` → `Ready(blocks↾c)`, ordered oldest first
- `Err` → `errors += 1`; `errors > RETRY_MAX` → `Drop(c)`, else `SendDownload(c)`

**`SendProcess(c)`** — guard `state = Ready(blocks)` ∧ `c.parent ∈ FC`; `c.state := Processing(blocks)`. Guarantees `OnProcess(R, result)` with `R = c.roots`, where `Ok` means all `blocks` are part of `FC` on return.

**`OnProcess(R, result)`** — for each `c ∈ owners(R)`:
- `Ok` → `loc ∖= c.roots`; drop `c`
- `Err` → `errors += 1`; `errors > RETRY_MAX` → `Drop(c)`, else `SendDownload(c)`

`Err` also `report_peer(first(owners(R)).peers)` — oldest only: import stops at the first bad block, and split halves share peers.

**`Disconnect(p)`** — remove `p` everywhere; `peers = ∅` → `Drop`.

**`Drop(x)`** — remove `x` and, transitively, every `c` whose `parent` ∈ `x.roots`; `loc ∖= x.roots`, and `x`'s `Discovering(next)` root if any.

**Prune** — after any insertion into `loc` (`Search`, `OnHeaders`): while `|loc| > ROOTS_MAX`, `Drop` chains ascending by `|peers|`.

## Invariants

1. `loc(r) = c` ⟺ `r ∈ c.roots ∨ c.state = Discovering(r)`.
2. `c.roots` contiguous by `parent_root`, tip first.
3. `p ∈ c.peers` ⟹ `p` claimed **every** root in `c.roots` ≡ `p` claimed `c.roots[0]`, since holding `r` implies holding its ancestors. A false or stale claim surfaces as `Err`.
4. `slot` strictly decreases along `c.roots`.
5. `Ready(blocks) ∨ Processing(blocks)` ⟹ `roots(blocks) = c.roots` ∧ `∀i>0. parent(blocks[i]) = blocks[i−1]`; `Processing` also ⟹ `parent(blocks[0]) ∈ FC`.
6. `state = Anchored(p)` ⟹ `p ∈ FC ∨ p ∈ dom(loc)`.

## Liveness

- Discovery terminates: `slot` strictly decreases (Inv 4), bounded below by `slot(finalized)`.
- With ≥1 honest peer holding the chain, every root reaches `FC` or is dropped.
