#!/bin/bash
# edr_tamper.sh: Tries to kill and tamper with EDR process and files
EDR_PROC="ultra_edr" # Change to your EDR process name
EDR_LOG="../logs/edr.log"
EDR_CFG="../configs/config.toml"

for i in {1..60}; do
  pkill -9 "$EDR_PROC" 2>/dev/null
  killall -9 "$EDR_PROC" 2>/dev/null
  echo "[TAMPER] Attempt $i: Killed EDR process" >> /tmp/edr_tamper.log
  echo "[TAMPER] Attempt $i: Corrupting log" >> /tmp/edr_tamper.log
  echo "TAMPERED" > "$EDR_LOG" 2>/dev/null
  echo "[TAMPER] Attempt $i: Corrupting config" >> /tmp/edr_tamper.log
  echo "TAMPERED" > "$EDR_CFG" 2>/dev/null
  sleep 1
done
