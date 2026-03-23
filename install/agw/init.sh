#!/bin/bash
# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.
#
# This bash script is an entrypoint for the HypershieldAgent container that manages
# the lifecycle of the agw process. It handles signal trapping, starts required
# background services, waits for dependencies, manages crash/restart logic for agw,
# and ensures graceful shutdown or recovery from failures.
# Use 'docker logs -f HypershieldAgent' to view the logs.
#

handle_sigterm() {
   echo "Caught SIGTERM!"
   pid=$(pgrep agw)
   echo agw pid is $pid
   kill -SIGTERM $pid
}

trap 'handle_sigterm' SIGTERM

echo "Starting HypershieldAgent init script"
# Start background services: chronyd and crond.
mkdir -p /data/volatile/logs
mkdir -p /var/NTP

# Start Fluent Bit logger.
# The static YAML config is installed at the same path AGW writes dynamically.
# AGW overwrites it on Init() and triggers hot_reload on config changes.
FLB_CONFIG=/data/hypershield/daflogger.yaml
FLB_LOG=/data/volatile/logs/fluent-bit.log
FLB_METRICS_URL=${FLB_METRICS_URL:-http://localhost:2020/api/v1/metrics}
FLB_READY_ATTEMPTS=${FLB_READY_ATTEMPTS:-60}
FLB_READY_SLEEP_SECONDS=${FLB_READY_SLEEP_SECONDS:-1}
/usr/bin/fluent-bit -Y -c "$FLB_CONFIG" >> "$FLB_LOG" 2>&1 &
FLB_PID=$!

wait_for_fluent_bit_ready() {
   local i
   for i in $(seq 1 "$FLB_READY_ATTEMPTS"); do
      if curl -fsS "$FLB_METRICS_URL" >/dev/null 2>&1; then
         echo "Fluent Bit is ready at $FLB_METRICS_URL"
         return 0
      fi
      if ! kill -0 "$FLB_PID" 2>/dev/null; then
         echo "Fluent Bit exited before becoming ready"
         return 1
      fi
      sleep "$FLB_READY_SLEEP_SECONDS"
   done
   echo "Timed out waiting for Fluent Bit readiness at $FLB_METRICS_URL"
   return 1
}

if ! wait_for_fluent_bit_ready; then
   exit 1
fi

ntpd -c /etc/ntpsec -l /data/volatile/logs/ntp.log
crond
# Load crontab file.
mkdir -p /root/.cache
cat /usr/src/app/crontab | crontab -
# Create necessary directories if they don't exist.
mkdir -p /iox_data/states

# Run agw process in the background.
# If agw exits with 143 (SIGTERM), it will exit the script gracefully.
# If agw exits with 139 (SIGSEGV), 134 (SIGABRT),
#  - it will restart the agw process after a 20 second sleep, for max_sigsegv_retries times.
# If agw exits with 200,
#  - it will restart the agw process after a 20 second sleep.
# For any other agw exit code, it stops restarting agw.
sigsegv_count=0
# Set a maximum number of retries for SIGSEGV/SIGABORT crashes to avoid infinite restart loops.
max_sigsegv_retries=3
while :
do
   rm -f /run/agw.sock

   # Wait for the gNMI server to become available before proceeding.
   while true; do
      sleep 1
      echo "Attempting to contact gNMI server at $NX_GRPC_IP:$NX_GRPC_PORT..."
      curl -k https://$NX_GRPC_IP:$NX_GRPC_PORT > /dev/null 2>&1 && break
   done
   echo "gNMI server running"

   # Check if NX_AGENT_HEADLESS_MODE is not enabled (i.e., not "1").
   hl=`cat /etc/sas.cfg | grep NX_AGENT_HEADLESS_MODE=1 | cut -d '=' -f2`
   if [ "$hl" != "1" ]; then
      echo "Check DNS resolution"

      # Record the start time.
      start=$(date +%s)
      echo start: $start

      # Try to resolve cisco.com using nslookup, retrying for up to 1 minute.
      while ! nslookup cisco.com; do
         echo "nslookup fails, retrying..."
         now=$(date +%s)
         echo now: $now
         duration=$((now - start))
         minutes=$((duration / 60))
         if [ $minutes -gt 1 ]; then
            break
         fi
         sleep 1
      done
   fi

   export GOTRACEBACK=crash
   # Start agw and redirect output to log file.
   /usr/src/app/agw \
     --flb-socket-path=/run/cisco/fluentbit_agw.sock \
     --flb-config-path=/data/hypershield/daflogger.yaml \
     >> /data/volatile/logs/agw.log 2>&1 &
   pid=$!
   wait $pid
   retVal=$?
   echo agw returns $retVal
   # Handle the exit code of agw.
   if [ $retVal -eq 143 ]; then
      # If agw was terminated by SIGTERM (graceful), exit the script gracefully.
      echo "agw terminated"
      exit 0
   fi

   # When agw receives a SIGSEGV, the Go runtime prints a stack trace (core) to stderr,
   # and then calls abort() which results in an exit code of 134 (SIGABRT).
   # Therefore, we check for both exit codes 139 (SIGSEGV) and 134 (SIGABRT) to handle crashes.
   if [ $retVal -eq 134 ] || [ $retVal -eq 139 ]; then
      # Record the current time of SIGSEGV/SIGABRT
      now=$(date +%s)
      # If last crash was more than 1 minute ago, reset the counter.
      if [ -z "$last_sigsegv_time" ] || [ $((now - last_sigsegv_time)) -gt 60 ]; then
         sigsegv_count=1
      else
         # This crash is happening at the same place as before, increment the counter.
         sigsegv_count=$((sigsegv_count + 1))
      fi

      if [ $sigsegv_count -gt $max_sigsegv_retries ]; then
         echo "agw received exit code $retVal, more than $max_sigsegv_retries consecutive times without a 1 minute gap, not restarting"
         break
      fi
      # Restart agw after a 20 second sleep.
      last_sigsegv_time=$now
      echo "agw received exit code $retVal, restarting agw (attempt $sigsegv_count/$max_sigsegv_retries)"
      sleep 20
      continue
   fi
   # Reset the SIGSEGV/SIGABRT counter if agw exited with any other code.
   sigsegv_count=0
   last_sigsegv_time=""

   # If agw exits with code 200, restart agw after a 20 second sleep.
   # Exit code 200 is used by agw to request a restart, for well-known reasons.
   # For any other exit code, do not restart agw.
   if [ $retVal -ne 200 ]; then
      echo "agw exited with code $retVal, not restarting"
      break
   fi
   sleep 20
done

# On agw exit, start a sleep loop
s=$(date)
echo "Starting sleeping loop: $s"
while :
do
   sleep 10
   if [ -e /tmp/init_exit ]; then
     exit 0
   fi
done
