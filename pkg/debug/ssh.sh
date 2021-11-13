#!/bin/sh

# setting things up for being able to access linux kernel symbols
echo 0 >  /proc/sys/kernel/kptr_restrict
echo -1 > /proc/sys/kernel/perf_event_paranoid

[ ! -d "/persist/.sshkeys" ] && mkdir /persist/.sshkeys && chmod 0700 /persist/.sshkeys

KEYS=$(find /persist/.sshkeys -name 'ssh_host_*_key')
if [ -z "$KEYS" ]; then
    ssh-keygen -A >/dev/null 2>/dev/null
    cp /etc/ssh/ssh_host_*_key /persist/.sshkeys/.
else
    cp /persist/.sshkeys/ssh_host_*_key /etc/ssh/.
fi

mkdir -p /run/debug/usr/bin
cp /usr/bin/lshw /run/debug/usr/bin/.
cp /usr/bin/spec.sh /run/debug/usr/bin/.

exec /usr/sbin/sshd -D -e
