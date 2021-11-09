#!/usr/bin/env python3

# The purpose of this script is to compare a list of file names that were accessed during testing
# against all the file names in the consensus-spec-tests repository. It then checks to see which files
# were not accessed and returns an error if any non-intentionally-ignored files are detected.
#
# The ultimate goal is to detect any accidentally-missed spec tests.

import os
import sys

# First argument should the path to a file which contains a list of accessed file names.
accessed_files_filename = sys.argv[1]

# Second argument should be the path to the consensus-spec-tests directory.
tests_dir_filename = sys.argv[2]

# If any of the file names found in the consensus-spec-tests directory *starts with* one of the
# following strings, we will assume they are to be ignored (i.e., we are purposefully *not* running
# the spec tests).
excluded_paths = [
    # Merge tests
    "tests/minimal/merge",
    "tests/mainnet/merge",
    # Eth1Block
    #
    # Intentionally omitted, as per https://github.com/sigp/lighthouse/issues/1835
    "tests/minimal/phase0/ssz_static/Eth1Block/",
    "tests/mainnet/phase0/ssz_static/Eth1Block/",
    "tests/minimal/altair/ssz_static/Eth1Block/",
    "tests/mainnet/altair/ssz_static/Eth1Block/",
    # LightClientStore
    "tests/minimal/altair/ssz_static/LightClientStore",
    "tests/mainnet/altair/ssz_static/LightClientStore",
    # LightClientUpdate
    "tests/minimal/altair/ssz_static/LightClientUpdate",
    "tests/mainnet/altair/ssz_static/LightClientUpdate",
    # LightClientSnapshot
    "tests/minimal/altair/ssz_static/LightClientSnapshot",
    "tests/mainnet/altair/ssz_static/LightClientSnapshot",
    # Fork choice
    "tests/mainnet/phase0/fork_choice",
    "tests/minimal/phase0/fork_choice",
    "tests/mainnet/altair/fork_choice",
    "tests/minimal/altair/fork_choice",
    # Merkle-proof tests for light clients
    "tests/mainnet/altair/merkle/single_proof/pyspec_tests/",
    "tests/minimal/altair/merkle/single_proof/pyspec_tests/"
]

def normalize_path(path):
	return path.split("consensus-spec-tests/", )[1]

# Determine the list of filenames which were accessed during tests.
passed = set()
for line in open(accessed_files_filename, 'r').readlines():
    file = normalize_path(line.strip().strip('"'))
    passed.add(file)

missed = set()
accessed_files = 0
excluded_files = 0

# Iterate all files in the tests directory, ensure that all files were either accessed
# or intentionally missed.
for root, dirs, files in os.walk(tests_dir_filename):
   for name in files:
      name = normalize_path(os.path.join(root, name))
      if name not in passed:
          excluded = False
          for excluded_path in excluded_paths:
              if name.startswith(excluded_path):
                  excluded = True
                  break
          if excluded:
              excluded_files += 1
          else:
              print(name)
              missed.add(name)
      else:
          accessed_files += 1

# Exit with an error if there were any files missed.
assert len(missed) == 0, "{} missed files".format(len(missed))

print("Accessed {} files ({} intentionally excluded)".format(accessed_files, excluded_files))
