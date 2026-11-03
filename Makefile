GO ?= go

.PHONY: build test vet fmt clean all

all: vet test build

build:
	$(GO) build ./...

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin dist
