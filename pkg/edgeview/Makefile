#
# example to build a docker image for edge-view, for query/client usage
# github build process may want to push the image into certain docker repository
#
edge-view-query:
	docker build -f Dockerfile.query -t edge-view-query .

#
# build the websocket server/dispatcher, should compile on a machine in the
# same architecture as the server runs the websocket dispather
#
wss-server:
	go build dispatcher/wss-server.go
