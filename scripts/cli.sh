#! /bin/bash

# Check if a lighthouse binary exists in the current branch.
maxperf=./target/maxperf/lighthouse
release=./target/release/lighthouse
debug=./target/debug/lighthouse

if [[ -f "$maxperf" ]]; then
    CMD="$maxperf"
elif [[ -f "$release" ]]; then
    CMD="$release"
elif [[ -f "$debug" ]]; then
    CMD="$debug"
else
    # No binary exists, build it.
    cargo build --locked
    CMD="$debug"
fi

# Remove the existing help text file if it exists.
rm -f -- cli.txt

# Store all help strings in variables.
bn=$($CMD bn --help)
vc=$($CMD vc --help)
wallet=$($CMD a wallet --help)

# Print all help strings to the cli.txt file.
printf "%s\n\n" "$bn" "$vc" "$wallet" >> cli.txt