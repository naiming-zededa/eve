FROM lfedge/eve-alpine:6.7.0 as build
ENV BUILD_PKGS libc-dev git gcc linux-headers go
ENV PKGS alpine-baselayout musl-utils iproute2 iptables
RUN eve-alpine-deploy.sh

COPY src/  /edge-view/.
COPY go.mod /edge-view/.
COPY go.sum /edge-view/.
WORKDIR /edge-view

RUN go build -o edge-view edge-view.go tcp.go proxy.go basics.go \
 websocket.go system.go network.go pubsub.go log-search.go copyfile.go
RUN strip edge-view
RUN cp edge-view /out/usr/bin
RUN cp edge-view-init.sh /out/usr/bin

FROM scratch
COPY --from=build /out/ /
RUN mkdir -p /tmp

ENV PATH="/run/debug/usr/bin:${PATH}"

WORKDIR /
ENTRYPOINT ["/usr/bin/edge-view-init.sh"]
CMD []