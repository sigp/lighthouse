# GitHub Issue & PR Guidelines

Guidelines for creating well-structured GitHub issues and PRs for Lighthouse.

## Issue Structure

### Start with Description

Always begin with `## Description`:

```markdown
## Description

We presently prune all knowledge of non-canonical blocks once they conflict with
finalization. The pruning is not always immediate, fork choice currently prunes
once the number of nodes reaches a threshold of 256.

It would be nice to develop a simple system for handling messages relating to
blocks that are non-canonical.
```

**Guidelines:**
- First paragraph: problem and brief solution
- Provide context about current behavior
- Link to related issues, PRs, or specs
- Be technical and specific

### Steps to Resolve (when applicable)

```markdown
## Steps to resolve

I see two ways to fix this: a strict approach, and a pragmatic one.

The strict approach would only check once the slot is finalized. This would have
0 false positives, but would be slower to detect missed blocks.

The pragmatic approach might be to only process `BeaconState`s from the canonical
chain. I don't have a strong preference between approaches.
```

**Guidelines:**
- Don't be overly prescriptive - present options
- Mention relevant constraints
- It's okay to say "I don't have a strong preference"

### Optional Sections

- `## Additional Info` - Edge cases, related issues
- `## Metrics` - Performance data, observations
- `## Version` - For bug reports

## Code References

**Use GitHub permalinks with commit hashes** so code renders properly:

```
https://github.com/sigp/lighthouse/blob/261322c3e3ee/beacon_node/beacon_processor/src/lib.rs#L809
```

Get commit hash: `git rev-parse unstable`

For line ranges: `#L809-L825`

## Writing Style

### Be Natural and Concise
- Direct and objective
- Precise technical terminology
- Avoid AI-sounding language

### Be Honest About Uncertainty
- Don't guess - ask questions
- Use tentative language when appropriate ("might", "I think")
- Present multiple options without picking one

### Think About Trade-offs
- Present multiple approaches
- Discuss pros and cons
- Consider backward compatibility
- Note performance implications

## Labels

**Type:** `bug`, `enhancement`, `optimization`, `code-quality`, `security`, `RFC`

**Component:** `database`, `HTTP-API`, `fork-choice`, `beacon-processor`, etc.

**Effort:** `good first issue`, `low-hanging-fruit`, `major-task`

## Pull Request Guidelines

```markdown
## Description

[What does this PR do? Why is it needed? Be concise and technical.]

Closes #[issue-number]

## Additional Info

[Breaking changes, performance impacts, migration steps, etc.]
```

### Commit Messages

Format:
- First line: Brief summary (imperative mood)
- Blank line
- Additional details if needed

```
Add custody info API for data columns

Implements `/lighthouse/custody/info` endpoint that returns custody group
count, custodied columns, and earliest available data column slot.
```

## Anti-Patterns

- Vague descriptions without details
- No code references when describing code
- Premature solutions without understanding the problem
- Making claims without validating against codebase

## Good Examples

- https://github.com/sigp/lighthouse/issues/6120
- https://github.com/sigp/lighthouse/issues/4388
- https://github.com/sigp/lighthouse/issues/8216
