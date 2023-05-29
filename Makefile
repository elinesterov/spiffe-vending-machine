VERSION ?= $(shell git describe --always --dirty)

.PHONY: build
build:
	go build -ldflags "-X github.com/elinesterov/spiffe-vending-machine/pkg/common/version.version=${VERSION}" -o ./bin/svmctl

.PHONY: clean
clean:
	rm svmctl