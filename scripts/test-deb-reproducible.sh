#!/bin/bash
#
# Test reproducibility of cargo-deb packages
#
# Usage: ./scripts/test-deb-reproducible.sh [RUST_TARGET]
#
# This script builds the same Debian package twice with clean builds in between,
# then compares them to ensure reproducible builds are working correctly.

set -euo pipefail

# Default target if not provided
RUST_TARGET="${1:-x86_64-unknown-linux-gnu}"

echo "🔄 Testing cargo-deb package reproducibility for ${RUST_TARGET}..."

# Check if diffoscope is available, install if needed
if ! command -v diffoscope &> /dev/null; then
    echo "📦 Installing diffoscope..."
    sudo apt-get update
    sudo apt-get install -y diffoscope binutils-multiarch
fi

# Clean up any existing test artifacts
echo "🧹 Cleaning up previous test artifacts..."
rm -f lighthouse_*.deb lighthouse-deb-*.deb *-diff.txt

# Build first package
echo "🔨 Building first package..."
make clean || true
make deb-cargo RUST_TARGET="${RUST_TARGET}"

FIRST_PACKAGE=$(find target/"${RUST_TARGET}"/debian -name "*.deb" | head -1)
if [ -n "$FIRST_PACKAGE" ]; then
    cp "$FIRST_PACKAGE" ./lighthouse-deb-build-1.deb
    echo "✅ First package built: $(basename "$FIRST_PACKAGE")"
else
    echo "❌ First package not found"
    exit 1
fi

# Build second package  
echo "🔨 Building second package..."
make clean || true
make deb-cargo RUST_TARGET="${RUST_TARGET}"

SECOND_PACKAGE=$(find target/"${RUST_TARGET}"/debian -name "*.deb" | head -1)
if [ -n "$SECOND_PACKAGE" ]; then
    cp "$SECOND_PACKAGE" ./lighthouse-deb-build-2.deb
    echo "✅ Second package built: $(basename "$SECOND_PACKAGE")"
else
    echo "❌ Second package not found"
    exit 1
fi

# Compare packages
echo "📊 Comparing packages..."
echo ""
echo "=== Package sizes ==="
ls -lah lighthouse-deb-build-*.deb

echo ""
echo "=== SHA256 checksums ==="
sha256sum lighthouse-deb-build-*.deb

echo ""
echo "=== Binary comparison ==="
if cmp -s lighthouse-deb-build-1.deb lighthouse-deb-build-2.deb; then
    echo "✅ SUCCESS: cargo-deb packages are identical!"
    echo "✅ Reproducible build PASSED for ${RUST_TARGET}"
    echo ""
    echo "🧹 Cleaning up test artifacts..."
    rm -f lighthouse-deb-build-*.deb
    exit 0
else
    echo "❌ FAILED: cargo-deb packages differ"
    echo "🔍 Running detailed analysis with diffoscope..."
    
    # Generate detailed diff report
    DIFF_FILE="cargo-deb-diff-${RUST_TARGET}.txt"
    if diffoscope --text lighthouse-deb-build-1.deb lighthouse-deb-build-2.deb > "$DIFF_FILE" 2>/dev/null; then
        echo "📄 Differences saved to ${DIFF_FILE}"
        echo "📄 Summary of first few differences:"
        head -20 "$DIFF_FILE" || true
    else
        echo "⚠️  diffoscope encountered issues, but differences were detected"
    fi
    
    echo ""
    echo "❌ Reproducible build FAILED for ${RUST_TARGET}"
    echo "💡 Tip: Check the diff file for details on what differs between builds"
    exit 1
fi
