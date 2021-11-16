#!/bin/sh
# in this query-edgeview.sh example script:
# - when ssh-mode is used, the ssh-key is mounted from ~/tmp/dev-ssh-key or your own location
# - when token is used, the websocket server endpoint "ip-addr:port" needs to be setup in $WSSADDRPORT environment
# - port mapping is optional for some query options
# - mount of download directory is optional and only for file copy option
# - the query docker container is build with 'make edge-view-query' in this directory
# - may need to tag and push the docker container to your own repository, setup the repo in $MYDOCKERREPO environment
if [ -z $MYDOCKERREPO ]; then
    echo "MYDOCKERREPO env variable needs to be set"
    exit 0
fi
if [ -z $WSSADDRPORT ]; then
    WSS=""
else
    WSS="-ws $WSSADDRPORT"
fi
if [ -f $HOME/tmp/dev-ssh-key ]; then
    MOUNTSSHKEY="-v $HOME/tmp/dev-ssh-key:/ssh-private-key"
else
    MOUNTSSHKEY=""
fi
docker run -it --rm -h=`hostname` $MOUNTSSHKEY -p 9001-9005:9001-9005 -v $HOME/tmp/download:/download ${MYDOCKERREOP}/edge-view-query $WSS "$@"
