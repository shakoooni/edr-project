#!/bin/bash
# edr_nas_stress.sh: Rapid file creation/deletion on NAS
NAS_PATH="/mnt/nas/edr_test_nas_stress"
mkdir -p "$NAS_PATH"
for i in {1..1000}; do
  dd if=/dev/urandom of="$NAS_PATH/file_$i.bin" bs=1K count=10 2>/dev/null
  rm -f "$NAS_PATH/file_$((i-1)).bin"
  sleep 0.05
done
rm -rf "$NAS_PATH"
