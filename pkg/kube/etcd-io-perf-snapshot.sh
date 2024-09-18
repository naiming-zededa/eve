#!/bin/bash
#
# etcd io perf snapshot
#
LOG_FILE=/persist/kubelog/io-perf-snapshot.log

split ()
{
    echo "****************************************"
}

{
    split
    date
    hostname
    cat /run/eve-release

    split
    echo "zpool iostat -vw"
    zpool iostat -vw

    split
    echo "zpool iostat -vw 1 3"
    zpool iostat -vw 1 3

    split
    echo "zpool iostat -vr"
    zpool iostat -vr

    split
    echo "zpool iostat -vr 1 3"
    zpool iostat -vr 1 3

    split
    echo "zfs txg sync time over 100ms:"
    awk '{if ($3 == "C" && $12 > 100000000) print $12 / 1000000 }' < /proc/spl/kstat/zfs/persist/txgs

    split
    echo "etcd slow fdatasync:"
    grep 'slow fdatasync' /persist/kubelog/k3s.log
    find /persist/kubelog/ -type f -name "k3s.log.?" -print0 | xargs -0 grep "slow fdatasync"

} >> $LOG_FILE 2>&1

