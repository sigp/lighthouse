#! /bin/bash

# A function to generate formatted .md files
write_to_file() {
    local cmd="$1"
    local file="$2"
    local program="$3"

    # Remove first line of cmd to get rid of commit specific numbers.
    cmd=${cmd#*$'\n'}

    # We need to add the header and the backticks to create the code block.
 printf "#%s\n\n\`\`\`\n%s\n\`\`\`" "$program" "$cmd" > "$file"
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

general=./help_general.md
bn=./help_bn.md
vc=./help_vc.md
am=./help_am.md

# create .md files
write_to_file "$general_cli" "$general" "Lighthouse General Commands"
write_to_file "$bn_cli" "$bn" "Beacon Node"
write_to_file "$vc_cli" "$vc" "Validator Client"
write_to_file "$am_cli" "$am" "Account Manager"

# create empty array to store variables for exit condition later
exist=()
update=()
for i in help_general help_bn help_vc help_am
do
    if [[ -f ./book/src/$i.md ]];  # first check if .md exists
    then 
        echo  "$i.md exists, continue to check for any changes"
        difference=$(diff ./book/src/$i.md $i.md)
        case1=false
        exist+=($case1)
        if [[ -z $difference ]]; # then check if any changes required
        then 
            case2=false
            update+=($case2)
            echo "$i.md is up to date"
        else
            cp $i.md ./book/src/$i.md
            echo "$i has been updated"
            case2=true
            update+=($case2)
        fi
    else
        echo "$i.md is not found, it will be created now"
        cp $i.md ./book/src/$i.md
        case1=true
        exist+=($case1)
    fi
done 

# use during testing to show exit conditions
echo "${exist[@]}"
echo "${update[@]}"

# exit condition, exit when .md does not exist or changes requried
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

# remove .md files in current directory
rm -f help_general.md help_bn.md help_vc.md help_am.md