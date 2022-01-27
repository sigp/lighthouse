#!/usr/bin/env bash
# Kill processes

set -Eeuo pipefail

# First parameter is the file with
# one pid per line.
if [ -f "$1" ]; then
  while read pid
    do
      echo killing $pid
      kill $pid
    done < $1
fi


