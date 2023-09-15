#! /bin/bash

# A function to generate formatted .md files
write_to_file() {
    local cmd="$1"
    local file="$2"
    local program="$3"

    # Remove first line of cmd to get rid of commit specific numbers.
    cmd=${cmd#*$'\n'}

    # We need to add the header and the backticks to create the code block.
 printf "# %s\n\n\`\`\`\n%s\n\`\`\`" "$program" "$cmd" > "$file"
}

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

# Store all help strings in variables.
general_cli=$($CMD --help)
bn_cli=$($CMD bn --help)
vc_cli=$($CMD vc --help)
am_cli=$($CMD am --help)
#vm_cli=$($CMD vm --help)

general=./help_general.md
bn=./help_bn.md
vc=./help_vc.md
am=./help_am.md
#vm=./help_vm.md

# create .md files
write_to_file "$general_cli" "$general" "Lighthouse General Commands"
write_to_file "$bn_cli" "$bn" "Beacon Node"
write_to_file "$vc_cli" "$vc" "Validator Client"
write_to_file "$am_cli" "$am" "Account Manager"
#write_to_file "$vm_cli" "$vm" "Validator Manager"

#input 1 = $1 = old files; input 2 = $2 = new files
old_files=(./book/src/help_general.md ./book/src/help_bn.md ./book/src/help_vc.md ./book/src/help_am.md)
new_files=($general $bn $vc $am)

exist=()
changes=()
check() {
if [[ -f $1 ]]; # check for existence of file
then
    diff=$(diff $1 $2)
    exist+=(false)
else
    cp $2 ./book/src
    exist+=(true)
fi

if [[ -z $diff ]]; # check for difference
then
    changes+=(false)
    return 1 # exit a function (i.e., do nothing)
else
    cp $2 ./book/src
    changes+=(true)
fi
}

# define changes as false
# changes=false
# call check function to check for each help file
check ${old_files[0]} ${new_files[0]}
check ${old_files[1]} ${new_files[1]}
check ${old_files[2]} ${new_files[2]}
check ${old_files[3]} ${new_files[3]}
#check ${old_files[4]} ${new_files[4]}

# remove help files
rm -f help_general.md help_bn.md help_vc.md help_am.md

echo "${exist[@]}"
echo "${changes[@]}"

if [[ ${exist[@]} == *"true"* && ${update[@]} == *"true"* ]];
then
    echo "exit 1 due to one or more .md file does not exist and changes updated."
    exit 1
elif [[  ${exist[@]} == *"true"* ]];
then
    echo "exit 1 due to one or more .md file does not exist"
    exit 1
elif [[ ${update[@]} == *"true"* ]];
then
    echo "exit 1 due to changes updated"
    exit 1
else
    echo "Task completed, no changes in CLI parameters"
fi

: '
check() {
if [[ -f $1 ]]; # check for existence of file
then 
    diff=$(diff $1 $2)
else
    cp $2 ./book/src
    changes=true 
fi

if [[ -z $diff ]]; # check for difference
then 
    return 1 # exit a function (i.e., do nothing)
else
    cp $2 ./book/src
    changes=true
fi
}

# define changes as false
changes=false
# call check function to check for each help file
check ${old_files[0]} ${new_files[0]}
check ${old_files[1]} ${new_files[1]}
check ${old_files[2]} ${new_files[2]}
check ${old_files[3]} ${new_files[3]}
#check ${old_files[4]} ${new_files[4]}

# remove help files
rm -f help_general.md help_bn.md help_vc.md help_am.md

# only exit at the very end
if [[ $changes == true ]]; then
    echo "CLI parameters are not up to date. Run \"make cli\" to update, then commit the changes"
    exit 1
else
    echo "CLI parameters are up to date."
    exit 0
fi
'