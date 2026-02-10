# Lighthouse Code Review Guidelines

Code review guidelines based on patterns from Lighthouse maintainers.

## Core Principles

- **Correctness** over clever code
- **Clarity** through good documentation and naming
- **Safety** through proper error handling and panic avoidance
- **Maintainability** for long-term health

## Critical: Consensus Crate (`consensus/` excluding `types/`)

**Extra scrutiny required** - bugs here cause consensus failures.

### Requirements

1. **Safe Math Only**
   ```rust
   // NEVER
   let result = a + b;

   // ALWAYS
   let result = a.saturating_add(b);
   // or use safe_arith crate
   let result = a.safe_add(b)?;
   ```

2. **Zero Panics**
   - No `.unwrap()`, `.expect()`, array indexing `[i]`
   - Return `Result` or `Option` instead

3. **Deterministic Behavior**
   - Identical results across all platforms
   - No undefined behavior

## Panic Avoidance (All Code)

```rust
// NEVER at runtime
let value = option.unwrap();
let item = array[1];

// ALWAYS
let value = option.ok_or(Error::Missing)?;
let item = array.get(1)?;

// Only acceptable during startup for CLI/config validation
let flag = matches.get_one::<String>("flag")
    .expect("Required due to clap validation");
```

## Code Clarity

### Variable Naming
```rust
// BAD - ambiguous
let bb = ...;
let bl = ...;

// GOOD - clear
let beacon_block = ...;
let blob = ...;
```

### Comments
- Explain the "why" not just the "what"
- All `TODO` comments must link to a GitHub issue
- Remove dead/commented-out code

## Error Handling

### Don't Silently Swallow Errors
```rust
// BAD
self.store.get_info().unwrap_or(None)

// GOOD
self.store.get_info().unwrap_or_else(|e| {
    error!(self.log, "Failed to read info"; "error" => ?e);
    None
})
```

### Check Return Values
Ask: "What happens if this returns `Ok(Failed)`?" Don't ignore results that might indicate failure.

## Performance & Concurrency

### Lock Safety
- Document lock ordering requirements
- Keep lock scopes narrow
- Seek detailed review for lock-related changes
- Use `try_read` when falling back to an alternative is acceptable
- Use blocking `read` when alternative is more expensive (e.g., state reconstruction)

### Async Patterns
```rust
// NEVER block in async context
async fn handler() {
    expensive_computation(); // blocks runtime
}

// ALWAYS spawn blocking
async fn handler() {
    tokio::task::spawn_blocking(|| expensive_computation()).await?;
}
```

### Rayon
- Use scoped rayon pools from beacon processor
- Avoid global thread pool (causes CPU oversubscription)

## Review Process

### Focus on Actionable Issues

**Limit to 3-5 key comments.** Prioritize:
1. Correctness issues - bugs, race conditions, panics
2. Missing test coverage - especially edge cases
3. Complex logic needing documentation
4. API design concerns

**Don't comment on:**
- Minor style issues
- Things caught by CI (formatting, linting)
- Nice-to-haves that aren't important

### Keep Comments Natural and Minimal

**Tone**: Natural and conversational, not robotic.

**Good review comment:**
```
Missing test coverage for the None blobs path. The existing test at
`store_tests.rs:2874` still provides blobs. Should add a test passing
None to verify backfill handles this correctly.
```

**Good follow-up after author addresses comments:**
```
LGTM, thanks!
```
or
```
Thanks for the updates, looks good!
```

**Avoid:**
- Checklists or structured formatting (✅ Item 1 fixed...)
- Repeating what was fixed (makes it obvious it's AI-generated)
- Headers, subsections, "Summary" sections
- Verbose multi-paragraph explanations

### Use Natural Language

```
BAD (prescriptive):
"This violates coding standards which strictly prohibit runtime panics."

GOOD (conversational):
"Should we avoid `.expect()` here? This gets called in hot paths and
we typically try to avoid runtime panics outside of startup."
```

### Verify Before Commenting

- If CI passes, trust it - types/imports must exist
- Check the full diff, not just visible parts
- Ask for verification rather than asserting things are missing

## Common Review Patterns

### Fork-Specific Changes
- Verify production fork code path unchanged
- Check SSZ compatibility (field order)
- Verify rollback/error paths handle edge cases

### API Design
- Constructor signatures should be consistent
- Avoid `Option` parameters when value is always required

### Concurrency
- Lock ordering documented?
- Potential deadlocks?
- Race conditions?

### Error Handling
- Errors logged?
- Edge cases handled?
- Context provided with errors?

## Deep Review Techniques

### Verify Against Specifications
- Read the actual spec in `./consensus-specs/`
- Compare formulas exactly
- Check constant values match spec definitions

### Trace Data Flow End-to-End
For new config fields:
1. Config file - Does YAML contain the field?
2. Config struct - Is it parsed with serde attributes?
3. apply_to_chain_spec - Is it actually applied?
4. Runtime usage - Used correctly everywhere?

### Check Error Handling Fallbacks
Examine every `.unwrap_or()`, `.unwrap_or_else()`:
- If the fallback triggers, does code behave correctly?
- Does it silently degrade or fail loudly?

### Look for Incomplete Migrations
When a PR changes a pattern across the codebase:
- Search for old pattern - all occurrences updated?
- Check test files - often lag behind implementation

## Architecture & Design

### Avoid Dependency Bloat
- Question whether imports add unnecessary dependencies
- Consider feature flags for optional functionality
- Large imports when only primitives are needed may warrant a `core` or `primitives` feature

### Schema Migrations
- Database schema changes require migrations
- Don't forget to add migration code when changing stored types
- Review pattern: "Needs a schema migration"

### Backwards Compatibility
- Consider existing users when changing behavior
- Document breaking changes clearly
- Prefer additive changes when possible

## Anti-Patterns to Avoid

### Over-Engineering
- Don't add abstractions until needed
- Keep solutions simple and focused
- "Three similar lines of code is better than a premature abstraction"

### Unnecessary Complexity
- Avoid feature flags for simple changes
- Don't add fallbacks for scenarios that can't happen
- Trust internal code and framework guarantees

### Premature Optimization
- Optimize hot paths based on profiling, not assumptions
- Document performance considerations but don't over-optimize

### Hiding Important Information
- Don't use generic variable names when specific ones are clearer
- Don't skip logging just to keep code shorter
- Don't omit error context

## Design Principles

### Simplicity First
Question every layer of abstraction:
- Is this `Arc` needed, or is the inner type already `Clone`?
- Is this `Mutex` needed, or can ownership be restructured?
- Is this wrapper type adding value or just indirection?

If you can't articulate why a layer of abstraction exists, it probably shouldn't.

### High Cohesion
Group related state and behavior together. If two fields are always set together, used together, and invalid without each other, they belong in a struct.

## Before Approval Checklist

- [ ] No panics: No `.unwrap()`, `.expect()`, unchecked array indexing
- [ ] Consensus safe: If touching consensus crate, all arithmetic is safe
- [ ] Errors logged: Not silently swallowed
- [ ] Clear naming: Variable names are unambiguous
- [ ] TODOs linked: All TODOs have GitHub issue links
- [ ] Tests present: Non-trivial changes have tests
- [ ] Lock safety: Lock ordering is safe and documented
- [ ] No blocking: Async code doesn't block runtime
