BINARY := scredmanager
PREFIX ?= $(HOME)/.local

.PHONY: build test integration vet install clean

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go vet ./...
	go test ./...

integration:
	go test -tags darwin_integration ./internal/store/

install: build
	mkdir -p $(PREFIX)/bin
	install -m 0755 bin/$(BINARY) $(PREFIX)/bin/$(BINARY)

clean:
	rm -rf bin
