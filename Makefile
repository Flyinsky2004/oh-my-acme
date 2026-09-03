BIN_DIR := bin
VERSION ?= dev
LDFLAGS := -X github.com/Flyinsky2004/oh-my-acme/internal/server.Version=$(VERSION) \
           -X github.com/Flyinsky2004/oh-my-acme/internal/agent.Version=$(VERSION)
TAILWIND := ./node_modules/.bin/tailwindcss
WEB_CSS_SOURCE := internal/server/web/styles/app.css
WEB_CSS_OUTPUT := internal/server/web/static/app.css

.PHONY: all build build-server build-agent test vet fmt clean web-css web-css-watch web-css-check

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

web-css:
	$(TAILWIND) -i $(WEB_CSS_SOURCE) -o $(WEB_CSS_OUTPUT) --minify

web-css-watch:
	$(TAILWIND) -i $(WEB_CSS_SOURCE) -o $(WEB_CSS_OUTPUT) --watch

web-css-check:
	@tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	$(TAILWIND) -i $(WEB_CSS_SOURCE) -o "$$tmp" --minify; \
	if ! cmp -s $(WEB_CSS_OUTPUT) "$$tmp"; then \
		echo "$(WEB_CSS_OUTPUT) is stale; run 'make web-css'"; \
		exit 1; \
	fi

clean:
	rm -rf $(BIN_DIR) dist
