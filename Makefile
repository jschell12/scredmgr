BINARY := scredmanager
PREFIX ?= $(HOME)/.local

.PHONY: build test integration vet install clean gui gui-run gui-audit

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go vet ./...
	go test ./...

integration:
	go test -tags darwin_integration ./internal/store/ ./internal/cli/

install: build
	mkdir -p $(PREFIX)/bin
	install -m 0755 bin/$(BINARY) $(PREFIX)/bin/$(BINARY)

gui:
	cd gui/src-tauri && cargo build --release

gui-run:
	cd gui/src-tauri && cargo run

# Security discipline rule 6: the GUI must have no keychain code path.
gui-audit:
	@cd gui/src-tauri && ! cargo tree 2>/dev/null | grep -iE 'keychain|security-framework' \
		&& echo "OK: no keychain/Security.framework dependency in gui/"

clean:
	rm -rf bin gui/src-tauri/target
