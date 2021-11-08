#!/bin/sh

while true;
do
  sleep 5
  PID=$(pgrep /usr/bin/edge-view)
  if [ -z "$PID" ]; then
    if [ -f /run/edgeview/edge-view-token ]; then
      TOKEN=`cat /run/edgeview/edge-view-token`
      WSADDR=`cat /run/edgeview/edge-view-wss-addr`
      /usr/bin/edge-view -server -ws "$WSADDR" -token "$TOKEN" &
      PID=$(pgrep /usr/bin/edge-view)
      echo "started edge-view with pid $PID"
    fi
  else
    if [ ! -f /run/edgeview/edge-view-token ]; then
      kill -9 $PID
      echo "edge-view killed"
    fi
  fi
done
