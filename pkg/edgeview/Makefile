#
# example to build a docker image for edge-view, for query/client usage
#
edge-view-query:
	docker build -f Dockerfile.query -t edge-view-query .

#
# build the websocket server/dispatcher, should compile on a linux machine
#
wss-server:
	go build dispatcher/wss-server.go
