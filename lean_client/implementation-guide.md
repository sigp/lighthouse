# Zeam Node Implementation Guide

This document provides a comprehensive technical guide to understanding the core data flows within the Zeam consensus node, including fork choice mechanics, database persistence, gossip message handling, signature verification, and attestation processing.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Hierarchy](#component-hierarchy)
3. [Fork Choice Algorithm](#fork-choice-algorithm)
4. [Data Flow: Fork Choice to Database](#data-flow-fork-choice-to-database)
5. [Gossip Message Handling](#gossip-message-handling)
6. [Signature Verification](#signature-verification)
7. [Attestation Flow](#attestation-flow)
8. [Database Schema](#database-schema)
9. [Event Broadcasting](#event-broadcasting)

---

## Architecture Overview

Zeam implements a beacon chain consensus client with the following core responsibilities:

- **Block Processing**: Receiving, validating, and applying blocks to the chain state
- **Fork Choice**: Determining the canonical chain head using a weighted tree algorithm
- **Attestation Handling**: Processing validator votes and updating fork choice weights
- **State Persistence**: Storing blocks, states, and indices in RocksDB
- **Network Communication**: Participating in peer-to-peer gossip and request/response protocols

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              BeamNode                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │   Network   │  │ BeamChain   │  │  Database   │  │ ValidatorClient │ │
│  │  (libp2p)   │  │             │  │  (RocksDB)  │  │                 │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ │
│         │                │                │                  │          │
│         └────────────────┼────────────────┴──────────────────┘          │
│                          │                                              │
│                   ┌──────┴──────┐                                       │
│                   │ ForkChoice  │                                       │
│                   │ (in-memory) │                                       │
│                   └─────────────┘                                       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Hierarchy

### BeamNode (`pkgs/node/src/node.zig`)

The top-level orchestrator that initializes and connects all subsystems:

```zig
pub const NodeOpts = struct {
    allocator: Allocator,
    db: database.Db,           // Persistent storage
    network: ?*networks.NetworkHandle,
    clock: *clock.Clock,
    // ...
};
```

### BeamChain (`pkgs/node/src/chain.zig`)

The central coordination layer that:
- Manages the `ForkChoice` instance
- Processes incoming blocks and attestations
- Coordinates state transitions via the STF module
- Persists data to the database
- Emits events for external subscribers

### ForkChoice (`pkgs/node/src/forkchoice.zig`)

An **in-memory** component implementing the LMD-GHOST (Latest Message Driven Greediest Heaviest Observed SubTree) algorithm:
- Maintains a tree of `ProtoNode` entries (lightweight block metadata)
- Tracks validator attestations and their weights
- Computes the canonical chain head
- Does **not** store full block or state data

### Database (`pkgs/database/`)

RocksDB-backed persistent storage with SSZ serialization:
- Stores full `SignedBlockWithAttestation` objects
- Stores full `BeamState` objects
- Maintains slot-to-root indices for finalized and unfinalized blocks

---

## Fork Choice Algorithm

### Core Data Structures

#### ProtoArray

The `ProtoArray` manages a compact tree representation of the block chain:

```zig
pub const ProtoArray = struct {
    nodes: std.ArrayList(ProtoNode),      // All known blocks as nodes
    indices: std.AutoHashMap(types.Root, usize),  // block_root → node index
    // ...
};
```

#### ProtoNode

Each node represents a simplified view of a block:

```zig
pub const ProtoNode = struct {
    slot: types.Slot,
    root: types.Root,           // Block root (hash)
    parent: ?usize,             // Index of parent node
    targetRoot: types.Root,     // Epoch boundary block root
    stateRoot: types.Root,
    justifiedCheckpoint: types.Checkpoint,
    finalizedCheckpoint: types.Checkpoint,
    weight: i64,                // Accumulated attestation weight
    bestChild: ?usize,          // Index of best child
    bestDescendant: ?usize,     // Index of best descendant (for head calculation)
};
```

#### ForkChoiceStore

Tracks finalization progress:

```zig
pub const ForkChoiceStore = struct {
    latest_justified: types.Checkpoint,
    latest_finalized: types.Checkpoint,
};
```

#### AttestationTracker

Manages validator attestation state:

```zig
pub const AttestationTracker = struct {
    latestKnown: std.AutoHashMap(types.ValidatorIndex, types.Attestation),
    latestNew: std.AutoHashMap(types.ValidatorIndex, types.Attestation),
    appliedIndex: ?usize,
};
```

### Head Selection Algorithm

The `updateHead()` function traverses the tree from the justified checkpoint:

```zig
pub fn updateHead(self: *Self) void {
    // 1. Start from latest justified checkpoint
    const justifiedRoot = self.fcStore.latest_justified.root;
    var bestNode = self.protoArray.getNodeFromRoot(justifiedRoot);
    
    // 2. Follow bestDescendant pointers down the tree
    while (bestNode.bestDescendant) |descendantIdx| {
        bestNode = self.protoArray.nodes.items[descendantIdx];
    }
    
    // 3. The leaf of this traversal is the head
    self.head = bestNode.root;
}
```

### Weight Calculation

When attestations are processed, weights propagate up the tree:

```zig
pub fn applyDeltas(self: *Self) void {
    // For each new attestation
    for (attestation in newAttestations) {
        // Add weight to target block
        targetNode.weight += validatorEffectiveBalance;
        
        // Propagate up to ancestors
        var node = targetNode;
        while (node.parent) |parentIdx| {
            // Recalculate best child based on new weights
            self.updateBestChildAndDescendant(parentIdx);
            node = self.nodes.items[parentIdx];
        }
    }
}
```

---

## Data Flow: Fork Choice to Database

The critical insight is that **ForkChoice operates purely in-memory** with lightweight metadata, while **BeamChain coordinates persistence** of full objects.

### Block Processing Flow

```
                    ┌──────────────────┐
                    │  Incoming Block  │
                    │ (from gossip/RPC)│
                    └────────┬─────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │     BeamChain.onBlock()      │
              │  1. Compute block_root (SSZ) │
              │  2. Verify signatures (STF)  │
              │  3. Apply state transition   │
              └──────────────┬───────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────┐ ┌───────────────┐ ┌─────────────────┐
│ ForkChoice      │ │ Internal Map  │ │ Database        │
│ .onBlock()      │ │ self.states   │ │ .updateBlockDb()│
│                 │ │               │ │                 │
│ Stores:         │ │ Stores:       │ │ Stores:         │
│ - ProtoNode     │ │ - BeamState   │ │ - Full block    │
│   (metadata)    │ │   (full obj)  │ │ - Full state    │
│ - Block root    │ │               │ │ - Slot indices  │
│ - Checkpoints   │ │               │ │                 │
└─────────────────┘ └───────────────┘ └─────────────────┘
```

### Detailed Steps in `BeamChain.onBlock()`

```zig
pub fn onBlock(self: *Self, signedBlock: types.SignedBlockWithAttestation, blockInfo: CachedProcessedBlockInfo) ![]types.Root {
    const block = signedBlock.message.block;
    
    // Step 1: Compute block root
    var block_root: types.Root = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, block, &block_root, self.allocator);
    
    // Step 2: Apply state transition (computes post_state)
    var post_state = try self.getParentState(block.parent_root);
    try stf.apply_transition(self.allocator, &post_state, block, .{ .logger = self.logger });
    
    // Step 3: Create ProtoBlock for ForkChoice (lightweight metadata only)
    const proto_block = forkchoice.ProtoBlock{
        .slot = block.slot,
        .root = block_root,
        .parentRoot = block.parent_root,
        .targetRoot = computeTargetRoot(block),
        .stateRoot = block.state_root,
        .justifiedCheckpoint = post_state.current_justified_checkpoint,
        .finalizedCheckpoint = post_state.finalized_checkpoint,
    };
    
    // Step 4: Update in-memory fork choice
    try self.forkChoice.onBlock(proto_block, &post_state);
    
    // Step 5: Store full state in internal map (for future state lookups)
    try self.states.put(block_root, post_state);
    
    // Step 6: Persist to database
    try self.updateBlockDb(signedBlock, block_root, post_state, block.slot, previousFinalizedSlot);
    
    // Step 7: Process attestations included in the block
    for (block.body.attestations.constSlice()) |attestation| {
        try self.forkChoice.onAttestation(attestation, true);  // true = from block
    }
    
    // Step 8: Update head and emit events
    self.forkChoice.updateHead();
    try self.emitHeadEvent(block_root);
}
```

### Database Persistence in `updateBlockDb()`

```zig
fn updateBlockDb(
    self: *Self,
    signedBlock: types.SignedBlockWithAttestation,
    blockRoot: types.Root,
    postState: types.BeamState,
    slot: types.Slot,
    finalizedSlot: types.Slot,
) !void {
    // Create atomic write batch
    var batch = self.db.initWriteBatch();
    
    // Store full block (SSZ serialized)
    self.db.saveBlock(database.DbBlocksNamespace, blockRoot, signedBlock);
    
    // Store full state (SSZ serialized)
    self.db.saveState(database.DbStatesNamespace, blockRoot, postState);
    
    // Update finalized slot indices if finalization advanced
    try self.processFinalizationAdvancement(&batch, previousFinalizedSlot, finalizedSlot);
    
    // Atomic commit
    self.db.commit(&batch);
}
```

### Finalization Index Updates

When finalization advances, the system queries ForkChoice for the canonical finalized chain:

```zig
fn processFinalizationAdvancement(
    self: *Self,
    batch: *database.Db.WriteBatch,
    previousFinalizedSlot: types.Slot,
    finalizedSlot: types.Slot,
) !void {
    if (finalizedSlot <= previousFinalizedSlot) return;
    
    // Get canonical finalized roots from ForkChoice
    const finalizedRoots = try self.forkChoice.getAncestorsOfFinalized();
    
    // Store slot → root mappings for finalized blocks
    for (finalizedRoots) |entry| {
        batch.putFinalizedSlotIndex(entry.slot, entry.root);
    }
}
```

---

## Gossip Message Handling

### Message Types

The network layer delivers two primary gossip message types:

```zig
pub const GossipMessage = union(enum) {
    block: types.SignedBlockWithAttestation,
    attestation: types.SignedAttestation,
};
```

### Processing Pipeline

```
┌────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  P2P Network   │────▶│  BeamNode       │────▶│  BeamChain       │
│  (libp2p)      │     │  .onGossip()    │     │  .onGossip()     │
└────────────────┘     └─────────────────┘     └──────────────────┘
                                                       │
                              ┌─────────────────────────┴─────────────────────────┐
                              │                                                   │
                              ▼                                                   ▼
                    ┌──────────────────┐                             ┌──────────────────┐
                    │  Block Handler   │                             │ Attestation      │
                    │                  │                             │ Handler          │
                    │  1. validateBlock│                             │                  │
                    │  2. fetchMissing │                             │ 1. validateAttn  │
                    │  3. verifySignatures                           │ 2. verifySignature
                    │  4. onBlock()    │                             │ 3. onAttestation │
                    └──────────────────┘                             └──────────────────┘
```

### Block Gossip Handler

```zig
pub fn onGossip(self: *Self, data: *const networks.GossipMessage) !void {
    switch (data.*) {
        .block => |signedBlock| {
            // Step 1: Validate block structure and parent existence
            try self.validateBlock(&signedBlock);
            
            // Step 2: Check if parent exists, fetch if missing
            const parentRoot = signedBlock.message.block.parent_root;
            if (!self.forkChoice.hasBlock(parentRoot)) {
                // Request missing blocks via RPC
                try self.network.requestBlocksByRoot(&[_]types.Root{parentRoot});
                return;  // Will retry when parent arrives
            }
            
            // Step 3: Verify all signatures
            try stf.verifySignatures(self.allocator, parentState, &signedBlock);
            
            // Step 4: Process the block
            try self.onBlock(signedBlock, .{});
        },
        
        .attestation => |signedAttestation| {
            try self.onAttestation(signedAttestation);
        },
    }
}
```

### Block Validation Rules

```zig
fn validateBlock(self: *Self, signedBlock: *const types.SignedBlockWithAttestation) !void {
    const block = signedBlock.message.block;
    
    // Parent must exist in fork choice
    if (!self.forkChoice.protoArray.hasRoot(block.parent_root)) {
        return error.UnknownParent;
    }
    
    // Slot must be greater than parent slot
    const parentNode = self.forkChoice.protoArray.getNode(block.parent_root);
    if (block.slot <= parentNode.slot) {
        return error.InvalidSlot;
    }
    
    // Block must not be from the future
    if (block.slot > self.clock.currentSlot() + 1) {
        return error.FutureBlock;
    }
}
```

---

## Signature Verification

Zeam uses **XMSS** (eXtended Merkle Signature Scheme), a post-quantum hash-based signature algorithm.

### Signature Structure

Each `SignedBlockWithAttestation` contains multiple signatures:

```zig
pub const SignedBlockWithAttestation = struct {
    message: SignedBlock,
    signature: BoundedArray(SIGBYTES, MAX_ATTESTATIONS + 1),  // N attestation sigs + 1 proposer sig
};
```

### Verification Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    stf.verifySignatures()                               │
│                                                                         │
│  SignedBlockWithAttestation                                             │
│  ├── message.block.body.attestations[0..N]  ◄──┐                        │
│  ├── message.proposer_attestation           ◄──┼── Each verified with   │
│  └── signature[0..N+1]                      ◄──┘   corresponding sig    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Implementation Details

```zig
pub fn verifySignatures(
    allocator: Allocator,
    state: *const types.BeamState,
    signed_block: *const types.SignedBlockWithAttestation,
) !void {
    const attestations = signed_block.message.block.body.attestations.constSlice();
    const signatures = signed_block.signature.constSlice();

    // Invariant: exactly one signature per attestation + one for proposer
    if (attestations.len + 1 != signatures.len) {
        return StateTransitionError.InvalidBlockSignatures;
    }

    // Verify each body attestation
    for (attestations, 0..) |attestation, i| {
        try verifySingleAttestation(allocator, state, &attestation, &signatures[i]);
    }

    // Verify proposer attestation (last signature)
    try verifySingleAttestation(
        allocator,
        state,
        &signed_block.message.proposer_attestation,
        &signatures[signatures.len - 1],
    );
}
```

### Single Attestation Verification

```zig
pub fn verifySingleAttestation(
    allocator: Allocator,
    state: *const types.BeamState,
    attestation: *const types.Attestation,
    signatureBytes: *const types.SIGBYTES,
) !void {
    // Step 1: Look up validator from state
    const validatorIndex: usize = @intCast(attestation.validator_id);
    const validators = state.validators.constSlice();
    
    if (validatorIndex >= validators.len) {
        return StateTransitionError.InvalidValidatorId;
    }
    
    const validator = &validators[validatorIndex];
    
    // Step 2: Extract XMSS public key from validator record
    const pubkey = validator.getPubkey();
    
    // Step 3: Compute attestation message hash (signing root)
    var message: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.Attestation, attestation.*, &message, allocator);
    
    // Step 4: Get epoch for XMSS index derivation
    const epoch: u32 = @intCast(attestation.data.slot);
    
    // Step 5: Verify XMSS signature
    try xmss.verifyBincode(pubkey, &message, epoch, signatureBytes);
}
```

### XMSS Verification Process

```
┌──────────────────┐
│   Attestation    │
│   (plaintext)    │
└────────┬─────────┘
         │ SSZ hashTreeRoot
         ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Message Hash    │────▶│  XMSS Verify     │◀────│  Validator       │
│  (32 bytes)      │     │                  │     │  Public Key      │
└──────────────────┘     │  - Epoch index   │     └──────────────────┘
                         │  - Signature     │
                         │  - Auth path     │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │  Valid / Invalid │
                         └──────────────────┘
```

---

## Attestation Flow

Attestations are validator votes for a specific chain head. They influence fork choice weights and contribute to finalization.

### Attestation Data Structure

```zig
pub const Attestation = struct {
    validator_id: ValidatorIndex,
    data: AttestationData,
};

pub const AttestationData = struct {
    slot: Slot,                    // Slot being attested to
    index: u64,                    // Committee index
    beacon_block_root: Root,       // Block being voted for (head)
    source: Checkpoint,            // Justified checkpoint
    target: Checkpoint,            // Target checkpoint (epoch boundary)
};
```

### Complete Attestation Processing Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ATTESTATION SOURCES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐                    ┌─────────────────────────────────┐  │
│  │  Gossip Network │                    │  Block Body (attestations[])   │  │
│  │  (loose attns)  │                    │  (aggregated/included attns)   │  │
│  └────────┬────────┘                    └──────────────┬──────────────────┘  │
│           │                                            │                     │
│           │ fromGossip = false                         │ fromBlock = true    │
│           ▼                                            ▼                     │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    BeamChain.onAttestation()                          │   │
│  └───────────────────────────────┬──────────────────────────────────────┘   │
│                                  │                                           │
└──────────────────────────────────┼───────────────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │     Step 1: VALIDATION       │
                    │     validateAttestation()    │
                    │                              │
                    │  • Source checkpoint exists  │
                    │  • Target checkpoint exists  │
                    │  • Head block exists         │
                    │  • Slot relationships valid  │
                    │  • Not from future           │
                    │  • Timeliness (if gossip)    │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Step 2: SIGNATURE VERIFY    │
                    │  stf.verifySingleAttestation │
                    │                              │
                    │  • Lookup validator pubkey   │
                    │  • Hash attestation (SSZ)    │
                    │  • XMSS verify signature     │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │   Step 3: FORK CHOICE        │
                    │   forkChoice.onAttestation() │
                    │                              │
                    │  • Track in AttestationTracker
                    │  • Queue for weight update   │
                    └──────────────┬───────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │   Step 4: WEIGHT UPDATE      │
                    │   (on next updateHead)       │
                    │                              │
                    │  • Apply deltas to nodes     │
                    │  • Propagate up tree         │
                    │  • Recalculate best child    │
                    └──────────────────────────────┘
```

### Attestation Validation

```zig
fn validateAttestation(self: *Self, attestation: *const types.Attestation, fromBlock: bool) !void {
    const data = attestation.data;
    
    // 1. Source checkpoint must exist in fork choice
    if (!self.forkChoice.protoArray.hasRoot(data.source.root)) {
        return error.UnknownSourceCheckpoint;
    }
    
    // 2. Target checkpoint must exist
    if (!self.forkChoice.protoArray.hasRoot(data.target.root)) {
        return error.UnknownTargetCheckpoint;
    }
    
    // 3. Attested head block must exist
    if (!self.forkChoice.protoArray.hasRoot(data.beacon_block_root)) {
        return error.UnknownHeadBlock;
    }
    
    // 4. Target must be descendant of source
    const targetNode = self.forkChoice.protoArray.getNode(data.target.root);
    if (!self.forkChoice.isAncestor(data.source.root, data.target.root)) {
        return error.InvalidTargetSource;
    }
    
    // 5. Timeliness check (gossip attestations only)
    if (!fromBlock) {
        const currentSlot = self.clock.currentSlot();
        if (data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE < currentSlot) {
            return error.AttestationTooOld;
        }
    }
}
```

### Fork Choice Attestation Tracking

```zig
pub fn onAttestation(self: *Self, attestation: types.Attestation, fromBlock: bool) !void {
    const validatorId = attestation.validator_id;
    
    // Check if we already have a newer attestation from this validator
    if (self.attestations.latestKnown.get(validatorId)) |existing| {
        if (existing.data.slot >= attestation.data.slot) {
            return;  // Already have equal or newer attestation
        }
    }
    
    // Update latest known attestation
    try self.attestations.latestKnown.put(validatorId, attestation);
    
    // Queue for weight application if not yet applied
    if (self.attestations.appliedIndex == null or 
        self.protoArray.getIndexFromRoot(attestation.data.target.root) > self.attestations.appliedIndex.?) {
        try self.attestations.latestNew.put(validatorId, attestation);
    }
}
```

### Weight Application

```zig
pub fn applyAttestationDeltas(self: *Self, state: *const types.BeamState) void {
    var deltas = std.AutoHashMap(usize, i64).init(self.allocator);
    
    // Calculate weight changes from new attestations
    var iter = self.attestations.latestNew.iterator();
    while (iter.next()) |entry| {
        const attestation = entry.value_ptr.*;
        const validatorId = entry.key_ptr.*;
        
        // Get validator effective balance
        const balance = state.validators.items[validatorId].effective_balance;
        
        // Get target node index
        const targetIdx = self.protoArray.getIndexFromRoot(attestation.data.target.root);
        
        // Add weight to target
        const current = deltas.get(targetIdx) orelse 0;
        try deltas.put(targetIdx, current + @intCast(balance));
    }
    
    // Apply deltas and propagate
    self.protoArray.applyScoreChanges(deltas);
    
    // Clear processed attestations
    self.attestations.latestNew.clearRetainingCapacity();
}
```

---

## Database Schema

### Column Namespaces

| Namespace | Key Format | Value Type | Description |
|-----------|------------|------------|-------------|
| `DbBlocksNamespace` | `block_root` (32 bytes) | SSZ(`SignedBlockWithAttestation`) | Full block data |
| `DbStatesNamespace` | `block_root` (32 bytes) | SSZ(`BeamState`) | Post-state after block |
| `DbFinalizedSlotsNamespace` | `slot` (8 bytes BE) | `block_root` (32 bytes) | Finalized slot index |
| `DbUnfinalizedSlotsNamespace` | `slot` (8 bytes BE) | `block_root` (32 bytes) | Unfinalized slot index |

### Key Formatting

```zig
pub fn formatBlockKey(block_root: types.Root) [32]u8 {
    return block_root;  // Block root is already 32 bytes
}

pub fn formatSlotKey(slot: types.Slot) [8]u8 {
    return std.mem.toBytes(std.mem.nativeToBig(u64, slot));
}
```

### SSZ Serialization

All complex types are serialized using SSZ (Simple Serialize):

```zig
pub fn saveBlock(self: *Self, comptime cn: ColumnNamespace, block_root: types.Root, block: types.SignedBlockWithAttestation) void {
    var buffer = std.ArrayList(u8).init(self.allocator);
    ssz.serialize(types.SignedBlockWithAttestation, block, &buffer);
    
    const key = cn.formatKey(block_root);
    self.db.put(cn.column, &key, buffer.items);
}

pub fn loadBlock(self: *Self, comptime cn: ColumnNamespace, block_root: types.Root) ?types.SignedBlockWithAttestation {
    const key = cn.formatKey(block_root);
    const data = self.db.get(cn.column, &key) orelse return null;
    
    return ssz.deserialize(types.SignedBlockWithAttestation, data, self.allocator);
}
```

---

## Event Broadcasting

The system emits Server-Sent Events (SSE) for external consumers via the API layer.

### Event Types

```zig
pub const ChainEvent = union(enum) {
    head: HeadEvent,
    justified: CheckpointEvent,
    finalized: CheckpointEvent,
};

pub const HeadEvent = struct {
    slot: types.Slot,
    block_root: types.Root,
    state_root: types.Root,
};

pub const CheckpointEvent = struct {
    epoch: types.Epoch,
    root: types.Root,
};
```

### Emission Points

Events are emitted at key moments in `BeamChain`:

```zig
// After updating head
fn emitHeadEvent(self: *Self, newHead: types.Root) !void {
    const node = self.forkChoice.protoArray.getNode(newHead);
    try self.eventBroadcaster.emit(.{
        .head = .{
            .slot = node.slot,
            .block_root = newHead,
            .state_root = node.stateRoot,
        },
    });
}

// After justification advances
fn emitJustifiedEvent(self: *Self, checkpoint: types.Checkpoint) !void {
    try self.eventBroadcaster.emit(.{
        .justified = .{
            .epoch = checkpoint.epoch,
            .root = checkpoint.root,
        },
    });
}

// After finalization advances
fn emitFinalizedEvent(self: *Self, checkpoint: types.Checkpoint) !void {
    try self.eventBroadcaster.emit(.{
        .finalized = .{
            .epoch = checkpoint.epoch,
            .root = checkpoint.root,
        },
    });
}
```

---

## Summary

| Component | Responsibility | Storage Type |
|-----------|---------------|--------------|
| **ForkChoice** | Head selection, weight tracking | In-memory (ProtoNodes) |
| **BeamChain** | Coordination, validation, persistence | Orchestrator |
| **Database** | Persistent storage | RocksDB (SSZ encoded) |
| **STF** | State transitions, signature verification | Stateless |
| **Network** | Gossip, RPC | P2P (libp2p) |

The architecture maintains a clear separation between:
1. **Hot data** (ForkChoice) - lightweight, in-memory, fast access for consensus
2. **Cold data** (Database) - complete objects, persistent, for historical queries and recovery
3. **Coordination** (BeamChain) - bridges the two, ensuring consistency and emitting events

---

## Roadmap to Parity for the Rust `lean_client`

The current Rust implementation mirrors only a subset of the Zeam architecture described in this guide. To reach feature parity, implement the following end-to-end plan, proceeding roughly in the order shown:

1. **Introduce an orchestrator layer**
   - Add a `LeanChain` (or similar) service that owns fork choice, state caches, network handles, and persistence instead of concentrating logic inside `ValidatorService`.
   - Ensure the orchestrator exposes explicit hooks for ticking intervals, block import, attestation ingestion, metrics, and logging.

2. **Extend the proto array and vote tracking**
   - Port Zeam’s proto-array structure (best child/descendant pointers, delta propagation, proposer boost, execution payload validation flags).
   - Maintain vote trackers (`latestKnown`, `latestNew`) so attestation processing is O(number of validators) instead of reloading all attestations from disk.

3. **Align database schemas and caching**
   - Introduce column namespaces (blocks, states, attestations, checkpoints, finalized slots) and wrap writes in atomic batches.
   - Maintain an in-memory cache of recent states keyed by block root so block processing and block production no longer reread SSZ blobs repeatedly.
   - Persist slot→root indices for finalized and unfinalized ranges to support fast lookups and pruning.

4. **Upgrade attestation validation and fork-choice integration**
   - Enforce source/target ancestry checks, timeliness rules, and committee membership before accepting gossip attestations.
   - When promoting attestations, compute deltas against the proto array rather than storing everything on disk and recalculating.
   - Rework safe-target updates to reuse the in-memory fork-choice view instead of recomputing from the store.

5. **Complete XMSS signature handling**
   - Implement XMSS verification for block bodies and gossip attestations, including PRF index management and per-validator keystores.
   - Support multiple local validators (matching Zeam’s registration APIs) instead of a single hard-coded index.

6. **Add event broadcasting, metrics, and structured logging**
   - Mirror Zeam’s SSE broadcaster so external tooling can subscribe to head/justified/finalized events.
  - Integrate metrics counters (validator count, peer count, fork-choice timings) and adopt structured log rotation similar to `BeamChain`.

7. **Enhance networking parity**
   - Extend the network service with req/resp RPC handlers to fetch parent blocks on demand, track pending requests, and manage bootstrap retries.
   - Surface peer status updates and expose a peer set API for the orchestrator and CLI tooling.

8. **Harden block and attestation ingestion**
   - Validate parent availability, signature correctness, and slot ordering before registering blocks with fork choice.
   - Push block body attestations through the same verification stack used for gossip so fork choice sees a single, consistent entry point.

9. **Testing and fixtures**
   - Port Zeam’s fork-choice and state-transition test rigs (or build Rust equivalents) to guard the richer logic.
   - Create integration tests that iterate slot/interval loops, asserting on emitted events, head roots, and database indices.

Executing this roadmap will bring the Rust `lean_client` to parity with the Zig implementation described above while maintaining the modular structure required for future extensions (execution engine integration, slasher, multi-validator support, etc.).

### Orchestrator Refactor Plan

1. **Phase 1 – Extract fork-choice management (Done)**
   - Introduced `LeanChain` to encapsulate the `LeanStore`, proto array, and vote tracking.
   - Redirected block and attestation handlers to delegate registration and weight updates to the new coordinator.

2. **Phase 2 – Isolate storage mutations**
   - Move all direct database reads/writes out of `ValidatorService`, exposing small helper methods on `LeanChain`.
   - Add explicit APIs for state caching (e.g., `get_state`, `put_state`) to prepare for in-memory hot caches.

3. **Phase 3 – Network/event integration**
   - Shift networking callbacks to the orchestrator layer: the network service should push events to `LeanChain`, which in turn triggers validator or metrics updates.
   - Stub out SSE/event broadcast hooks in Rust mirroring Zeam’s API module so that future telemetry can subscribe to head/finality changes.

4. **Phase 4 – Validator orchestration**
   - Allow `LeanChain` to track multiple validator assignments and expose scheduling helpers (proposer/attester lookup per slot).
   - Split `ValidatorService` into a lightweight duty engine that consumes orchestrator outputs (next proposal payload, attestation targets).

5. **Phase 5 – Persistence alignment**
   - Introduce columnar namespaces and batched writes inside `LeanChain`, matching Zeam’s RocksDB layout.
   - Implement finalized/unfinalized slot indices and expose pruning APIs.

Each phase should land as an incremental PR so that tooling, tests, and documentation evolve alongside the code. This staged approach avoids a monolithic rewrite while steadily converging on the Zeam architecture.
