#!/bin/sh

ForceNewlog=/config/Force-Use-Newlog
if [ -f "$ForceNewlog" ]; then
    echo "Force Use Newlog, rsyslog exit..."
else
    mkdir -p /run/watchdog/pid
    ./monitor-rsyslog.sh
fi