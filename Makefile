BINARY := scredmgr
PREFIX ?= $(HOME)/.local
# Stable code signature so Keychain "Always Allow" ACL grants survive rebuilds.
# Ad-hoc (linker) signatures change every build, which resets item ACLs and
# causes a password prompt per secret. Override with CODESIGN_ID=- for ad-hoc.
CODESIGN_ID ?= Apple Development
BUNDLE_ID := com.jschell12.scredmgr

.PHONY: build test integration vet install clean gui gui-run gui-audit

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)
	codesign -f -s "$(CODESIGN_ID)" --identifier $(BUNDLE_ID) bin/$(BINARY)

test:
	go vet ./...
	go test ./...

integration:
	go test -tags darwin_integration ./internal/store/ ./internal/cli/

install: build
	mkdir -p $(PREFIX)/bin
	install -m 0755 bin/$(BINARY) $(PREFIX)/bin/$(BINARY)
	# Compat shim: consumers that still call `scredmanager` keep working.
	ln -sf $(BINARY) $(PREFIX)/bin/scredmanager

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
