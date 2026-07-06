# Code Review Task

You are reviewing code for the Lighthouse project.

## Required Reading

**Before reviewing, read `.ai/CODE_REVIEW.md`** for Lighthouse-specific safety requirements and review etiquette.

## Focus Areas

1. **Consensus Crate Safety** (if applicable)
   - Safe math operations (saturating_*, checked_*)
   - Zero panics
   - Deterministic behavior

2. **General Code Safety**
   - No `.unwrap()` or `.expect()` at runtime
   - No array indexing without bounds checks
   - Proper error handling

3. **Code Clarity**
   - Clear variable names (avoid ambiguous abbreviations)
   - Well-documented complex logic
   - TODOs linked to GitHub issues

4. **Error Handling**
   - Errors are logged, not silently swallowed
   - Edge cases are handled
   - Return values are checked

5. **Concurrency & Performance**
   - Lock ordering is safe
   - No blocking in async context
   - Proper use of rayon thread pools

## Output

- Keep to 3-5 actionable comments
- Use natural, conversational language
- Provide specific line references
- Ask questions rather than making demands

## After Review Discussion

If the developer corrects your feedback or you learn something new:

1. **Acknowledge and learn** - Note what you got wrong
2. **Offer to update docs** - Ask: "Should I update `.ai/CODE_REVIEW.md` with this lesson?"
3. **Format the lesson:**
   ```markdown
   ### Lesson: [Title]
   **Issue:** [What went wrong]
   **Feedback:** [What developer said]
   **Learning:** [What to do differently]
   ```

This keeps the review guidelines improving over time.
