#!/bin/sh

while true;
do
  sleep 10
  PID=$(pgrep /usr/bin/edge-view)
  if [ ! -f /run/edgeview/edge-view-config ]; then
    timediff=-1
  else
    now=$(date -u '+%s')
    notafter=$(grep "EvJWTExp:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
    timediff=$(( notafter - now ))
  fi
  if [ -z "$PID" ]; then
    if [ -f /run/edgeview/edge-view-config ] && [ $timediff -gt 0 ]; then
      CONFIGSUM=$(md5sum /run/edgeview/edge-view-config)
      TOKEN=$(grep "EvJWToken:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
      INSTNUM=$(grep "EdgeViewMultiInst:" /run/edgeview/edge-view-config | awk -F":" '{printf $2}')
      if [ -z ${INSTNUM} ]; then
        /usr/bin/edge-view -server -token "$TOKEN" &
      else
        a=0
        while [ $a -lt $INSTNUM ]
        do
          a=`expr $a + 1`
          /usr/bin/edge-view -server -inst "$a" -token "$TOKEN" &
        done
      fi
      PID=$(pgrep /usr/bin/edge-view)
      echo "started edge-view with pid $PID"
    fi
  else
    if [ $timediff -lt 0 ]; then
      kill -9 `echo "$PID"`
      echo "edge-view killed"
    else
      if [ -f /run/edgeview/edge-view-config ]; then
        NOWSUM=$(md5sum /run/edgeview/edge-view-config)
        if [ "$NOWSUM" != "$CONFIGSUM" ]; then
          kill -9 `echo "$PID"`
          echo "edge-view killed"
        fi
      fi
    fi
  fi
done
