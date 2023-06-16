#! /bin/bash

#echo "Enter the latest lighthouse version:"
#read version
version=4.2.0

#download lighthouse binary
binary="curl -LO https://github.com/sigp/lighthouse/releases/download/v$version/lighthouse-v$version-x86_64-unknown-linux-gnu.tar.gz" 

#download the binary to the present working directory
$binary 

#extract
tar xvf lighthouse-v$version-x86_64-unknown-linux-gnu.tar.gz

#remove
rm lighthouse-v$version-x86_64-unknown-linux-gnu.tar.gz

#outputs help text. the "&& echo >> cli.txt is to create a line space between the next output"
lighthouse --help | tee cli.txt && echo >> cli.txt

# account manager, the -a option means append, i.e., append  the  output so that all outputs are in a single file
lighthouse a --help | tee -a cli.txt && echo >> cli.txt
# subcommand under account
lighthouse a validator --help | tee -a cli.txt && echo >> cli.txt
lighthouse a validator modify --help | tee -a cli.txt && echo >> cli.txt
lighthouse a validator slashing-protection --help | tee -a cli.txt && echo >> cli.txt

lighthouse a wallet --help | tee -a cli.txt && echo >> cli.txt

# beacon node
lighthouse bn --help | tee -a cli.txt && echo >> cli.txt
# boot-node
lighthouse boot_node --help | tee -a cli.txt && echo >> cli.txt

# database manager
lighthouse db --help | tee -a cli.txt && echo >> cli.txt

# validator client
lighthouse vc --help | tee -a cli.txt && echo >> cli.txt
