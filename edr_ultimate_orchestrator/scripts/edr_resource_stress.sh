#!/bin/bash
# edr_resource_stress.sh: Stress CPU, memory, disk, and file descriptors
for i in {1..16}; do
  yes > /dev/null &
done
for i in {1..16}; do
  dd if=/dev/zero of=/tmp/edr_stress_$i bs=1M count=100 2>/dev/null &
done
ulimit -n 4096
for i in {1..4096}; do
  exec 3<>/tmp/edr_fd_$i || break
done
sleep 60
killall yes dd
rm -f /tmp/edr_stress_* /tmp/edr_fd_*
