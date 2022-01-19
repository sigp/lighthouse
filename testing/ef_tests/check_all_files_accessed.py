#!/usr/bin/env python3

# The purpose of this script is to compare a list of file names that were accessed during testing
# against all the file names in the consensus-spec-tests repository. It then checks to see which files
# were not accessed and returns an error if any non-intentionally-ignored files are detected.
#
# The ultimate goal is to detect any accidentally-missed spec tests.

import os
import re
import sys

# First argument should the path to a file which contains a list of accessed file names.
accessed_files_filename = sys.argv[1]

# Second argument should be the path to the consensus-spec-tests directory.
tests_dir_filename = sys.argv[2]

# If any of the file names found in the consensus-spec-tests directory *starts with* one of the
# following regular expressions, we will assume they are to be ignored (i.e., we are purposefully
# *not* running the spec tests).
excluded_paths = [
    # Eth1Block and PowBlock
    #
    # Intentionally omitted, as per https://github.com/sigp/lighthouse/issues/1835
    "tests/.*/.*/ssz_static/Eth1Block/",
    "tests/.*/.*/ssz_static/PowBlock/",
    # LightClientStore
    "tests/.*/.*/ssz_static/LightClientStore",
    # LightClientUpdate
    "tests/.*/.*/ssz_static/LightClientUpdate",
    # LightClientSnapshot
    "tests/.*/.*/ssz_static/LightClientSnapshot",
    # Merkle-proof tests for light clients
    "tests/.*/.*/merkle/single_proof",
    # One of the EF researchers likes to pack the tarballs on a Mac
    ".*\.DS_Store.*"
]

def normalize_path(path):
    return path.split("consensus-spec-tests/")[1]

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
            for excluded_path_regex in excluded_paths:
                if re.match(excluded_path_regex, name):
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
