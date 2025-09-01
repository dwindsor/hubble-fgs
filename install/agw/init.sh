#!/bin/bash

handle_sigterm() {
    echo "Caught SIGTERM!"
    pid=`ps ax|grep agw|grep -v grep|awk '{print $1}'`
    echo agw pid is $pid
    kill -SIGTERM $pid
}

trap 'handle_sigterm' SIGTERM

ntpd&
/etc/init.d/cron start
cat /usr/src/app/crontab | crontab -
mkdir -p /data/volatile/logs
mkdir -p /iox_data/states

#run agw in foreground
while :
do
   rm -f /run/agw.sock

   while true; do sleep 1; echo curl gnmi server; curl -k https://$NX_GRPC_IP:$NX_GRPC_PORT > /dev/null 2>&1 && break; done

   hl=`cat /etc/sas.cfg | grep NX_AGENT_HEADLESS_MODE=1 | cut -d '=' -f2`
   if [ "$hl" != "1" ]; then
      echo "Check DNS resolution"

      start=$(date +%s)
      echo start: $start
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
   /usr/src/app/agw >> /data/volatile/logs/agw.log 2>&1 &
   pid=$!
   wait $pid
   retVal=$?
   echo agw returns $retVal
   if [ $retVal -eq 143 ]; then
      echo terminated
      exit 0
   fi
   if [ $retVal -ne 200 ]; then
      break
   fi
   sleep 20
done

# on agw exit, start a sleep loop
s=$(date)
echo "Starting sleeping loop: $s"
while :
do
   sleep 10
   if [ -e /tmp/init_exit ]; then
     exit 0
   fi
done

