#!/bin/sh

while true;
do
  sleep 10
  PID=$(pgrep /usr/bin/edge-view)
  if [ ! -f /run/edgeview/edge-view-notafter ]; then
    timediff=1
  else
    now=$(date -u '+%s')
    notafter=$(cat /run/edgeview/edge-view-notafter)
    timediff=$(( notafter - now ))
  fi
  if [ -z "$PID" ]; then
    if [ -f /run/edgeview/edge-view-token ] && [ $timediff -gt 0 ]; then
      TOKEN=$(cat /run/edgeview/edge-view-token)
      WSADDR=$(cat /run/edgeview/edge-view-wss-addr)
      /usr/bin/edge-view -server -ws "$WSADDR" -token "$TOKEN" &
      PID=$(pgrep /usr/bin/edge-view)
      echo "started edge-view with pid $PID"
    fi
  else
    if [ ! -f /run/edgeview/edge-view-token ] || [ $timediff -lt 0 ]; then
      kill -9 "$PID"
      echo "edge-view killed"
    fi
  fi
done
