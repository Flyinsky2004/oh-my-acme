BIN_DIR := bin
VERSION ?= dev
LDFLAGS := -X github.com/Flyinsky2004/oh-my-acme/internal/server.Version=$(VERSION) \
           -X github.com/Flyinsky2004/oh-my-acme/internal/agent.Version=$(VERSION)

.PHONY: all build build-server build-agent test vet fmt clean

all: build test vet

build: build-server build-agent

build-server:
	mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/oh-my-acme-server ./cmd/server

build-agent:
	mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/oh-my-acme-agent ./cmd/agent

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd/ internal/

clean:
	rm -rf $(BIN_DIR) dist
