#! /bin/bash

# Check if a lighthouse binary exists in the current branch.
# -f means check if the file exists, to see all options, type "bash test" in a terminal
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
general=$($CMD --help)

# accoun manager
a=$($CMD a --help)

a_validator=$($CMD a validator --help)
a_validator_m=$($CMD a validator modify --help)
a_validator_s=$($CMD a validator slashing-protection --help)

a_wallet=$($CMD a wallet --help)

# beacon node

bn=$($CMD bn --help)

# boot-node
boot=$($CMD boot_node --help)

# data manager
dm=$($CMD db --help)

# validator client
vc=$($CMD vc --help)

# Print all help strings to the cli.txt file.
printf "%s\n\n" "$general" "$a" "$a_validator" "$a_validator_m" "$a_validator_s" "$a_wallet" "$bn" "$boot" "$dm" "$vc" "$wallet" >> cli.txt
