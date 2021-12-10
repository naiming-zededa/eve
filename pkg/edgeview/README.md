# Edgeview container in EVE

## ./src directory

It contains the main package of golang source for 'edgeview' container on EVE device. The 'edge-view-init.sh' script is started with the container and in a loop for start/stop the edgeview program base on the configurations

## ./dispatcher directory

It contains an example of golang source for 'edgeview' websocket dispatcher running in the cloud or in some VPN servers

## Dockerfiles

The 'Dockerfile' in the directory is used for EVE to build the 'edgeview' container running on EVE device

The 'dockerfile.query' in the directory is used to build 'edge-view-query' container which can be used for example by client on a remote laptop, or it can be run on some non-EVE linux server for 'edgeview' functionality

## Query script

The 'query-edgeview.sh' is an example of running the 'edge-view-query' docker container in the client computer

## Makefile

the 'Makefile' supports:

(1) 'make edge-view-query' to build the edge-view-query:latest docker container;

(2) 'make wss-server' to build a golang program for 'edgeview' websocket dispatcher. It needs to be run this compile on a Linux server if the websocket dispatcher will run in the same architecture;

## Help

On edge-vew client container, or 'edge-view-query', use '-h' or '-help' to see all the options, and one can do help on specific command option to get detail on the command.

 options:
  log/search-pattern [ -time start_time-end_time -json -type app|dev -extra num ]

  pub/ [baseosmgr domainmgr downloader global loguploader newlogd nim nodeagent tpmmgr vaultmgr volumemgr watcher zedagent zedclient zedmanager zedrouter]

  [acl app arp connectivity flow if mdns nslookup ping route socket speed tcp tcpdump trace url wireless]
  [app configitem cp datastore download hw lastreboot model newlog pci ps cipher usb shell volume]
