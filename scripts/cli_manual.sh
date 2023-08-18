#! /bin/bash


#read version
#read -p "Enter Lighthouse version: " version

version=4.3.0
#download lighthouse binary
binary="curl -LO https://github.com/sigp/lighthouse/releases/download/v$version/lighthouse-v$version-x86_64-unknown-linux-gnu.tar.gz" 

#download the binary to the present working directory
cd ./lighthouse/scripts
$binary 

#extract
tar xvf lighthouse-v$version-x86_64-unknown-linux-gnu.tar.gz

#remove
rm lighthouse-v$version-x86_64-unknown-linux-gnu.tar.gz

#outputs help text
general=$(./lighthouse --help)


# account manager
a=$(./lighthouse a --help)
# subcommand under account
a_validator=$(./lighthouse a validator --help)
a_validator_m=$(./lighthouse a validator modify --help)
a_validator_s=$(./lighthouse a validator slashing-protection --help)

a_wallet=$(./lighthouse a wallet --help)


# beacon node
bn=$(./lighthouse bn --help)

# boot-node
boot=$(./lighthouse boot_node --help)

# database manager
dm=$(./lighthouse db --help)

# validator client
vc=$(./lighthouse vc --help)

# remove binary file
rm lighthouse

# Print all help strings to the cli.txt file.
printf "%s\n\n" "$general" "$a" "$a_validator" "$a_validator_m" "$a_validator_s" "$a_wallet" "$bn" "$boot" "$dm" "$vc" "$wallet" >> cli_manual.txt
