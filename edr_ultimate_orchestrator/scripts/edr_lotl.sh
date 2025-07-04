#!/bin/bash
# edr_lotl.sh: Living-off-the-land and fileless attacks
for i in {1..30}; do
  bash -c 'echo "echo LOTL $RANDOM" | bash' &
  python3 -c 'import mmap; m = mmap.mmap(-1, 4096); m.write(b"LOTL"*1024)' &
  curl -s https://example.com | base64 | head -c 1000 > /dev/null &
  sleep 2
done
