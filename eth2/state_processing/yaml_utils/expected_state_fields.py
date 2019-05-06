#!/usr/bin/env python3

# Script to extract all the fields of the state mentioned in `expected_state` fields of tests
# in the `spec` directory. These fields can then be added to the `ExpectedState` struct.
# Might take a while to run.

import os, yaml

if __name__ == "__main__":
    yaml_files = (filename for filename in os.listdir("specs") if filename.endswith(".yaml"))
    parsed_yaml = (yaml.load(open("specs/" + filename, "r")) for filename in yaml_files)
    all_fields = set()
    for y in parsed_yaml:
        all_fields.update(*({key for key in case["expected_state"]} for case in y["test_cases"]))
    print(all_fields)
