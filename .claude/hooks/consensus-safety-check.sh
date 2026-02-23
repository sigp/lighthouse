#!/bin/bash
# Warn agent about unsafe patterns in critical code paths.
# Runs after Edit/Write. Non-blocking (warns, doesn't block).

set -uo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

# Only check .rs files in critical paths
if [[ -z "$FILE_PATH" ]]; then exit 0; fi
if [[ "$FILE_PATH" != *.rs ]]; then exit 0; fi
if [[ "$FILE_PATH" != *"consensus/"* ]] && [[ "$FILE_PATH" != *"beacon_chain/"* ]]; then exit 0; fi
if [[ "$FILE_PATH" == *"consensus/types/"* ]]; then exit 0; fi
if [[ "$FILE_PATH" == *"/tests/"* ]] || [[ "$FILE_PATH" == *"test_utils"* ]]; then exit 0; fi

WARNINGS=""

# Check for .unwrap() in changed lines
if git diff -- "$FILE_PATH" 2>/dev/null | grep '^\+' | grep -v '^\+\+\+' | grep -q '\.unwrap()'; then
    WARNINGS="${WARNINGS}\n- .unwrap() found in changed lines — use ? or .ok_or() instead"
fi

# Check for .expect( in changed lines
if git diff -- "$FILE_PATH" 2>/dev/null | grep '^\+' | grep -v '^\+\+\+' | grep -q '\.expect('; then
    WARNINGS="${WARNINGS}\n- .expect() found in changed lines — use ? or .ok_or() instead"
fi

# Check for direct array indexing [var] (catches foo[i], bar[idx], etc.)
if git diff -- "$FILE_PATH" 2>/dev/null | grep '^\+' | grep -v '^\+\+\+' | grep -qE '\[[a-z_]+\]'; then
    WARNINGS="${WARNINGS}\n- Possible direct array indexing — use .get() instead"
fi

# Consensus-specific: check for arithmetic operators (not in comments)
if [[ "$FILE_PATH" == *"consensus/"* ]] && [[ "$FILE_PATH" != *"consensus/types/"* ]]; then
    if git diff -- "$FILE_PATH" 2>/dev/null | grep '^\+' | grep -v '^\+\+\+' | grep -v '//' | grep -qE '[a-z0-9_)] [+\-\*] [a-z0-9_(]'; then
        WARNINGS="${WARNINGS}\n- Direct arithmetic in consensus crate — use saturating_add/checked_add/safe_arith"
    fi
fi

if [ -n "$WARNINGS" ]; then
    BASENAME=$(basename "$FILE_PATH")
    echo "{\"systemMessage\": \"Safety warnings for ${BASENAME}:${WARNINGS}\"}"
fi

exit 0
