#! /bin/python
import os
import sys

passed_tests_filename = sys.argv[1]
tests_dir_filename = sys.argv[2]

excluded_paths = [
    # Things from future phases
    "tests/mainnet/config/custody_game.yaml",
    "tests/mainnet/config/sharding.yaml",
    "tests/mainnet/config/merge.yaml",
    "tests/minimal/config/custody_game.yaml",
    "tests/minimal/config/sharding.yaml",
    "tests/minimal/config/merge.yaml",
    # Genesis Validity
    "tests/minimal/altair/genesis/validity",
    # Eth1Block
    "tests/minimal/phase0/ssz_static/Eth1Block/",
    "tests/mainnet/phase0/ssz_static/Eth1Block/",
    "tests/minimal/altair/ssz_static/Eth1Block/",
    "tests/mainnet/altair/ssz_static/Eth1Block/",
    # Rewards
    #
    # These are all commented-out since I think they *should not* be ignored.
    #
    # "tests/minimal/phase0/rewards",
    # "tests/mainnet/phase0/rewards",
    # "tests/minimal/altair/rewards",
    # "tests/mainnet/altair/rewards",
    # LightClientStore
    "tests/minimal/altair/ssz_static/LightClientStore",
    "tests/mainnet/altair/ssz_static/LightClientStore",
    # LightClientUpdate
    "tests/minimal/altair/ssz_static/LightClientUpdate",
    "tests/mainnet/altair/ssz_static/LightClientUpdate",
    # LightClientSnapshot
    "tests/minimal/altair/ssz_static/LightClientSnapshot",
    "tests/mainnet/altair/ssz_static/LightClientSnapshot",
    # ContributionAndProof
    "tests/minimal/altair/ssz_static/ContributionAndProof",
    "tests/mainnet/altair/ssz_static/ContributionAndProof",
    # SignedContributionAndProof
    "tests/minimal/altair/ssz_static/SignedContributionAndProof",
    "tests/mainnet/altair/ssz_static/SignedContributionAndProof",
    # SyncCommitteeContribution
    "tests/minimal/altair/ssz_static/SyncCommitteeContribution",
    "tests/mainnet/altair/ssz_static/SyncCommitteeContribution",
    # SyncCommitteeSignature
    "tests/minimal/altair/ssz_static/SyncCommitteeSignature",
    "tests/mainnet/altair/ssz_static/SyncCommitteeSignature",
    # SyncCommitteeSigningData
    "tests/minimal/altair/ssz_static/SyncCommitteeSigningData",
    "tests/mainnet/altair/ssz_static/SyncCommitteeSigningData",
    # Fork choice
    "tests/mainnet/phase0/fork_choice",
    "tests/minimal/phase0/fork_choice",
    "tests/mainnet/altair/fork_choice",
    "tests/minimal/altair/fork_choice",
]

def normalize_path(path):
	return path.split("eth2.0-spec-tests/", )[1]

# Determine the list of filenames which were accessed during tests.
passed = set()
for line in open(passed_tests_filename, 'r').readlines():
    file = normalize_path(line.strip().strip('"'))
    passed.add(file)

missed = set()
passed_tests = 0
excluded_tests = 0

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
              excluded_tests += 1
          else:
              print(name)
              missed.add(name)
      else:
          passed_tests += 1

# Exit with an error if there were any files missed.
assert len(missed) == 0, "{} missed tests".format(len(missed))

print("Passed {} tests ({} intentionally excluded)".format(passed_tests, excluded_tests))
