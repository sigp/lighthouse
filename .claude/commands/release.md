# Release Notes Generation Task

You are generating release notes for a new Lighthouse version.

## Input Required

- **Version number** (e.g., v8.1.0)
- **Base branch** (typically `stable` for previous release)
- **Release branch** (e.g., `release-v8.1`)
- **Release name** (Rick and Morty character - check existing to avoid duplicates)

## Step 1: Gather Changes

```bash
# Get commits between branches
git log --oneline origin/<base-branch>..origin/<release-branch>

# Check existing release names
gh release list --repo sigp/lighthouse --limit 50
```

## Step 2: Analyze PRs

For each PR:
1. Extract PR numbers from commit messages
2. Check for `backwards-incompat` label:
   ```bash
   gh pr view <PR> --repo sigp/lighthouse --json labels --jq '[.labels[].name] | join(",")'
   ```
3. Get PR details for context

## Step 3: Categorize

Group into sections (skip empty):
- **Breaking Changes** - schema changes, CLI changes, API changes
- **Performance Improvements** - user-noticeable optimizations
- **Validator Client Improvements** - VC-specific changes
- **Other Notable Changes** - new features, metrics
- **CLI Changes** - new/changed flags (note if BN or VC)
- **Bug Fixes** - significant user-facing fixes only

## Step 4: Write Release Notes

```markdown
## <Release Name>

## Summary

Lighthouse v<VERSION> includes <brief description>.

This is a <recommended/mandatory> upgrade for <target users>.

## <Section>

- **<Title>** (#<PR>): <User-facing description>

## Update Priority

| User Class        | Beacon Node | Validator Client |
|:------------------|:------------|:-----------------|
| Staking Users     | Low/Medium/High | Low/Medium/High |
| Non-Staking Users | Low/Medium/High | ---              |

## All Changes

- <commit title> (#<PR>)

## Binaries

[See pre-built binaries documentation.](https://lighthouse-book.sigmaprime.io/installation_binaries.html)
```

## Guidelines

- State **user impact**, not implementation details
- Avoid jargon users won't understand
- For CLI flags, mention if BN or VC
- Check PR descriptions for context

## Step 5: Generate Announcements

Create drafts for:
- **Email** - Formal, include priority table
- **Discord** - Tag @everyone, shorter
- **Twitter** - Single tweet, 2-3 highlights
