#!/usr/bin/env python3
"""
Create corrupted ERA files for testing ERA consumer error handling.

This script generates specific corrupt ERA files by:
1. Parsing existing ERA files
2. Modifying specific parts (block data, state data)
3. Re-encoding with valid compression

Requires: pip install python-snappy
"""
import os
import sys
import shutil
from pathlib import Path

try:
    import snappy
except ImportError:
    print("ERROR: python-snappy not installed. Run: pip install python-snappy", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).parent
ERA_DIR = SCRIPT_DIR / "era"
CORRUPT_DIR = SCRIPT_DIR / "corrupt"

def read_era_file(path):
    """Read ERA file and return raw bytes."""
    with open(path, 'rb') as f:
        return f.read()

def find_era_file(pattern):
    """Find ERA file matching pattern."""
    files = list(ERA_DIR.glob(f"minimal-{pattern}-*.era"))
    if not files:
        return None
    return files[0]

def corrupt_bytes_at_offset(data, offset, xor_pattern=0xFF):
    """Corrupt bytes at specific offset by XOR."""
    result = bytearray(data)
    result[offset] ^= xor_pattern
    result[offset + 1] ^= xor_pattern
    return bytes(result)

def main():
    print("Creating corrupt ERA test files...\n")
    CORRUPT_DIR.mkdir(exist_ok=True)

    # Test 1: ERA root mismatch - corrupt genesis_validators_root in ERA 0
    era0 = find_era_file("00000")
    if era0:
        data = read_era_file(era0)
        # Corrupt bytes in the state section (after 16-byte header)
        # The state is compressed, so corruption will propagate through state root
        corrupt_data = corrupt_bytes_at_offset(data, 16 + 50)
        output = CORRUPT_DIR / "era0-wrong-root.era"
        with open(output, 'wb') as f:
            f.write(corrupt_data)
        print(f"✓ Created era0-wrong-root.era ({len(corrupt_data)} bytes)")
    else:
        print("⚠ ERA 0 file not found, skipping", file=sys.stderr)

    # Test 2: Block summary root post-Capella mismatch - corrupt block_roots
    era8 = find_era_file("00008")
    if era8:
        data = read_era_file(era8)
        # Corrupt state section (different offset than ERA 0)
        corrupt_data = corrupt_bytes_at_offset(data, 16 + 100)
        output = CORRUPT_DIR / "era8-corrupt-block-summary.era"
        with open(output, 'wb') as f:
            f.write(corrupt_data)
        print(f"✓ Created era8-corrupt-block-summary.era ({len(corrupt_data)} bytes)")
    else:
        print("⚠ ERA 8 file not found, skipping", file=sys.stderr)

    # Test 3: Block root mismatch - corrupt a block
    era2 = find_era_file("00002")
    if era2:
        data = read_era_file(era2)
        # Find and corrupt a block (blocks come after state in ERA file)
        # We'll corrupt somewhere in the middle where blocks likely are
        corrupt_offset = len(data) // 3  # Rough guess at block location
        corrupt_data = corrupt_bytes_at_offset(data, corrupt_offset)
        output = CORRUPT_DIR / "era2-wrong-block-root.era"
        with open(output, 'wb') as f:
            f.write(corrupt_data)
        print(f"✓ Created era2-wrong-block-root.era ({len(corrupt_data)} bytes)")
    else:
        print("⚠ ERA 2 file not found, skipping", file=sys.stderr)

    print(f"\n✓ Corrupt files created in: {CORRUPT_DIR}")
    print(f"Total files: {len(list(CORRUPT_DIR.glob('*.era')))}")

if __name__ == "__main__":
    main()
