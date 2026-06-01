# Lighthouse AI Assistant Guide

This file provides guidance for AI assistants (Claude Code, Codex, etc.) working with Lighthouse.

## CRITICAL - Always Follow

After completing ANY code changes:
1. **MUST** run `cargo check` to verify compilation before considering task complete

Run `make install-hooks` if you have not already to install git hooks. Never skip git hooks. If cargo is not available install the toolchain.

## Quick Reference

```bash
# Build
make install                              # Build and install Lighthouse
cargo build --release                     # Standard release build

# Test (prefer targeted tests when iterating)
cargo nextest run -p <package>            # Test specific package
cargo nextest run -p <package> <test>     # Run individual test
make test                                 # Full test suite (~20 min)

# Lint
make lint                                 # Run Clippy
cargo fmt --all && make lint-fix          # Format and fix
```

## Before You Start

Read the relevant guide for your task:

| Task | Read This First |
|------|-----------------|
| **Code review** | `.ai/CODE_REVIEW.md` |
| **Creating issues/PRs** | `.ai/ISSUES.md` |
| **Development patterns** | `.ai/DEVELOPMENT.md` |

## Critical Rules (consensus failures or crashes)

### 1. No Panics at Runtime

```rust
// NEVER
let value = option.unwrap();
let item = array[1];

// ALWAYS
let value = option?;
let item = array.get(1)?;
```

Only acceptable during startup for CLI/config validation.

### 2. Consensus Crate: Safe Math Only

In `consensus/` (excluding `types/`), use saturating or checked arithmetic:

```rust
// NEVER
let result = a + b;

// ALWAYS
let result = a.saturating_add(b);
```

## Important Rules (bugs or performance issues)

### 3. Never Block Async

```rust
// NEVER
async fn handler() { expensive_computation(); }

// ALWAYS
async fn handler() {
    tokio::task::spawn_blocking(|| expensive_computation()).await?;
}
```

### 4. Lock Ordering

Document lock ordering to avoid deadlocks. See [`canonical_head.rs:9-32`](beacon_node/beacon_chain/src/canonical_head.rs) for the pattern.

### 5. Rayon Thread Pools

Use scoped rayon pools from beacon processor, not global pool. Global pool causes CPU oversubscription when beacon processor has allocated all CPUs.

## Good Practices

### 6. TODOs Need Issues

All `TODO` comments must link to a GitHub issue.

### 7. Clear Variable Names

Avoid ambiguous abbreviations (`bb`, `bl`). Use `beacon_block`, `blob`.

## Branch & PR Guidelines

- Branch from `unstable`, target `unstable` for PRs
- Run `cargo sort` when adding dependencies
- Run `make cli-local` when updating CLI flags

## Project Structure

```
beacon_node/           # Consensus client
  beacon_chain/        # State transition logic
  store/               # Database (hot/cold)
  network/             # P2P networking
  execution_layer/     # EL integration
validator_client/      # Validator duties
consensus/
  types/               # Core data structures
  fork_choice/         # Proto-array
```

See `.ai/DEVELOPMENT.md` for detailed architecture.

## Maintaining These Docs

**These AI docs should evolve based on real interactions.**

### After Code Reviews

If a developer corrects your review feedback or points out something you missed:
- Ask: "Should I update `.ai/CODE_REVIEW.md` with this lesson?"
- Add to the "Common Review Patterns" or create a new "Lessons Learned" entry
- Include: what went wrong, what the feedback was, what to do differently

### After PR/Issue Creation

If a developer refines your PR description or issue format:
- Ask: "Should I update `.ai/ISSUES.md` to capture this?"
- Document the preferred style or format

### After Development Work

If you learn something about the codebase architecture or patterns:
- Ask: "Should I update `.ai/DEVELOPMENT.md` with this?"
- Add to relevant section or create new patterns

### Format for Lessons

```markdown
### Lesson: [Brief Title]

**Context:** [What task were you doing?]
**Issue:** [What went wrong or was corrected?]
**Learning:** [What to do differently next time]
```

### When NOT to Update

- Minor preference differences (not worth documenting)
- One-off edge cases unlikely to recur
- Already covered by existing documentation
