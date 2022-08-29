#!/usr/bin/env bash

if [ "$EUID" -ne 0 ];
then
    echo "you must be root to run this script"
    exit 1
fi

echo core > /proc/sys/kernel/core_pattern

echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

