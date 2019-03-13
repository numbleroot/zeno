.PHONY: all clean build capnp

all: clean build

clean:
	go clean -i ./...

build:
	CGO_ENABLED=0 go build -a -ldflags '-w -extldflags "-static"'
