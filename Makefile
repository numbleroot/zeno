.PHONY: all clean build capnp

all: clean build

clean:
	go clean -i ./...

build:
	CGO_ENABLED=0 go build -a -ldflags '-w -extldflags "-static"'

capnp:
	capnp compile -I${GOPATH}/src/zombiezen.com/go/capnproto2/std -ogo rpc/*.capnp
