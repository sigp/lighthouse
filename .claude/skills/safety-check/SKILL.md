---
name: safety-check
description: Analyze changed code for safety violations — panics, unsafe arithmetic, missing bounds checks. Run this before submitting PRs.
---

# Safety Check

Analyze all changed Rust files for Lighthouse safety violations. This catches real bugs that cause consensus failures or crashes.

## Steps

1. **Get changed files**:
   ```bash
   git diff --name-only HEAD -- '*.rs'
   ```
   If no files changed, report "No Rust files modified" and stop.

2. **For each changed file**, read the diff and check for these violations:

### Critical (consensus/beacon_chain — excluding consensus/types/ and test files)

- **`.unwrap()`** — Must use `?`, `.ok_or()`, or `.ok_or_else()` instead. Only acceptable during startup for CLI/config validation.
- **`.expect(`** — Same as unwrap. Use `?` operator.
- **Direct indexing `[i]`** — Must use `.get(i)?` or `.get(i).ok_or()`. Direct indexing panics on out-of-bounds.
- **Direct arithmetic** (`a + b`, `a - b`, `a * b`) in `consensus/` (excluding `types/`) — Must use `a.saturating_add(b)`, `a.checked_add(b)`, or `safe_arith::SafeArith` methods. The `state_processing` crate enforces this at compile time via clippy deny attributes.

### Important (all non-test code)

- **`TODO` without issue link** — All TODO comments must reference a GitHub issue: `// TODO(#1234): description`
- **Ambiguous variable names** — `bb`, `bl`, `bc` should be `beacon_block`, `blob`, `beacon_chain`
- **Blocking in async** — `std::thread::sleep`, `std::sync::Mutex` in async functions. Use tokio equivalents.
- **Global rayon pool** — `rayon::iter::ParallelIterator` without scoped pool. Use beacon processor rayon pools.

3. **Run cargo check**:
   ```bash
   cargo check 2>&1
   ```
   Report any compilation errors.

4. **Run clippy**:
   ```bash
   make lint 2>&1
   ```
   Report any clippy warnings.

5. **Report findings** in this format:

   ```
   ## Safety Check Results

   ### Critical Issues
   - `file.rs:42` — .unwrap() in consensus code (use ? instead)

   ### Warnings
   - `file.rs:15` — TODO without issue link

   ### Compilation: PASS/FAIL
   ### Clippy: PASS/FAIL
   ```

   Include the specific line numbers and the offending code snippet for each finding.

## Notes

- Focus on **changed lines** (lines starting with `+` in the diff), not the entire file
- `consensus/state_processing/` already has compile-time enforcement via clippy deny attributes (`arithmetic_side_effects`, `unwrap_used`, `expect_used`, `indexing_slicing`, `panic`). Violations there will be caught by `cargo check`.
- `consensus/types/` is exempt from the strict arithmetic rules (it's pure data types)
- Test files (`**/tests/**`, `**/test_utils**`, `testing/**`) are exempt from unwrap/expect rules
