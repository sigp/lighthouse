#!/usr/bin/env bash
# Kill processes

set -Euo pipefail

# First parameter is the file with
# one pid per line.
if [ -f "$1" ]; then
  while read pid
    do
      # handle the case of blank lines
      [[ -n "$pid" ]] || continue

      # Kill the process if it exists 
      # (it might not if we stopped the start script before it finished starting all processes)
      if test -d /proc/"$pid"/; then
        echo killing $pid
        kill $pid
      fi
    done < $1
fi


