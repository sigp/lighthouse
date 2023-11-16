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

      echo killing $pid
      kill $pid || true
    done < $1
fi


