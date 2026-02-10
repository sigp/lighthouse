# Lighthouse Copilot Instructions

Guidelines for GitHub Copilot when working with Lighthouse.

## Critical Rules

1. **No panics at runtime** - Use `option?` and `array.get(i)?` instead of `.unwrap()` and `array[i]`
2. **Consensus crate safety** - Use `saturating_add/sub/mul` or `checked_*` in `consensus/` (excluding `types/`)
3. **Never block async** - Use `spawn_blocking` for expensive computations
4. **TODOs need issues** - All `TODO` comments must link to a GitHub issue

## Commands

```bash
make install          # Build Lighthouse
cargo nextest run -p <pkg>  # Test specific package
make lint             # Run Clippy
```

## More Information

See `CLAUDE.md` and `.ai/` directory for detailed guidelines:
- `.ai/CODE_REVIEW.md` - Review standards
- `.ai/ISSUES.md` - Issue/PR guidelines
- `.ai/DEVELOPMENT.md` - Architecture and patterns
