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

# Run the bash script to generate cli_manual.txt
#./cli_manual.sh

if [[ -f cli_manual.txt ]];
then
changes=$(diff -u cli_manual.txt cli.txt | tee update )
else
echo "cli_manual.txt is not found"
exit 1
fi

# compare two files to see if there are any differences: https://www.geeksforgeeks.org/cmp-command-in-linux-with-examples/
# compare=$(cmp cli_manual.txt cli.txt)

# to display the changes, commented for now
# echo $changes

# -z checks if a file is null: https://www.cyberciti.biz/faq/bash-shell-find-out-if-a-variable-has-null-value-or-not/
if [[ -z $changes ]];
then
    no_change=true
echo "cli_manual.txt is up to date"
exit 1
# if the difference is empty, use true to execute nothing: https://stackoverflow.com/questions/17583578/what-command-means-do-nothing-in-a-conditional-in-bash
else
patch cli_manual.txt update
echo "cli_manual.txt has been updated"
fi

# update cli_manual.sh
#patch cli_manual.txt patchfile.patch

