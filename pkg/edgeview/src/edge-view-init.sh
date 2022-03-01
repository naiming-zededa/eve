#!/bin/sh

while true;
do
  sleep 10
  PID=$(pgrep /usr/bin/edge-view)
  if [ ! -f /run/edgeview/edge-view-config ]; then
    timediff=1
  else
    now=$(date -u '+%s')
    notafter=$(grep "EvJWTExp:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
    timediff=$(( notafter - now ))
  fi
  if [ -z "$PID" ]; then
    if [ -f /run/edgeview/edge-view-config ] && [ $timediff -gt 0 ]; then
      TOKEN=$(grep "EvJWToken:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
      /usr/bin/edge-view -server -token "$TOKEN" &
      PID=$(pgrep /usr/bin/edge-view)
      echo "started edge-view with pid $PID"
    fi
  else
    if [ $timediff -lt 0 ]; then
      kill -9 "$PID"
      echo "edge-view killed"
    fi
  fi
done
