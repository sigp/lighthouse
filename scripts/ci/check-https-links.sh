#!/bin/bash

# Check for insecure HTTP links in Cargo.toml files
# This script ensures all git dependencies use HTTPS instead of HTTP
#
# This addresses the security concern raised in:
# https://github.com/sigp/lighthouse/issues/8106

set -e

# Find all Cargo.toml files, excluding those in target/ directories
cargo_toml_files=$(find . -name "Cargo.toml" -type f ! -path "*/target/*")

# Track if we found any HTTP links
found_http_links=false

echo "Checking for HTTP links in Cargo.toml files..."

# Check each Cargo.toml file
for file in $cargo_toml_files; do
    # Check for HTTP links (but not HTTPS)
    # We look for patterns like: git = "http://..." or url = "http://..."
    # Using -E for extended regex to handle whitespace variations
    http_links=$(grep -nE '(git|url)\s*=\s*"http://' "$file" 2>/dev/null || true)

    if [ -n "$http_links" ]; then
        echo "ERROR: Found HTTP link(s) in $file:"
        echo "$http_links"
        found_http_links=true
    fi
done

if [ "$found_http_links" = true ]; then
    echo ""
    echo "Please replace all HTTP links with HTTPS links in the Cargo.toml files above."
    echo "For example, change: git = \"http://github.com/...\""
    echo "                to: git = \"https://github.com/...\""
    exit 1
else
    echo "✓ All Cargo.toml files use HTTPS links."
    exit 0
fi

