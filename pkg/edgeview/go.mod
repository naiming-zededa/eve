module github.com/edge-view

go 1.15

replace github.com/lf-edge/eve/api/go => github.com/lf-edge/eve/api/go v0.0.0-20210924190522-88fdfcdeb176

require (
	github.com/gorilla/websocket v1.4.2
	github.com/lf-edge/eve/pkg/pillar v0.0.0-20220212170811-1f774097af31
	github.com/opencontainers/image-spec v1.0.1
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
)
