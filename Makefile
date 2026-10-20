BINARY := scredmgr
PREFIX ?= $(HOME)/.local
# Stable code signature so Keychain "Always Allow" ACL grants survive rebuilds.
# Ad-hoc (linker) signatures change every build, which resets item ACLs and
# causes a password prompt per secret. Override with CODESIGN_ID=- for ad-hoc.
CODESIGN_ID ?= Apple Development
BUNDLE_ID := com.jschell12.scredmgr
APP := bin/$(BINARY).app
APP_DIR ?= $(HOME)/Applications
LSREGISTER := /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

.PHONY: build build-linux test integration vet install app install-app clean gui gui-run gui-audit

build:
	go build -o bin/$(BINARY) ./cmd/$(BINARY)
	codesign -f -s "$(CODESIGN_ID)" --identifier $(BUNDLE_ID) bin/$(BINARY)

# Linux binaries use the encrypted FileStore backend (no keychain, no codesign).
build-linux:
	GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY)-linux-amd64 ./cmd/$(BINARY)
	GOOS=linux GOARCH=arm64 go build -o bin/$(BINARY)-linux-arm64 ./cmd/$(BINARY)

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

# The same binary inside a minimal app bundle. macOS Local Network Privacy
# attributes a connection to an app bundle and remembers the user's answer per
# bundle id; a bare CLI run by launchd has no bundle, so it is denied without a
# prompt. See "Local network access from launchd" in the README.
app: build
	rm -rf $(APP)
	mkdir -p $(APP)/Contents/MacOS
	cp packaging/macos/Info.plist $(APP)/Contents/Info.plist
	cp bin/$(BINARY) $(APP)/Contents/MacOS/$(BINARY)
	codesign -f -s "$(CODESIGN_ID)" $(APP)
	packaging/macos/check-app.sh $(APP) $(BUNDLE_ID)

# Installs the bundle, registers it with LaunchServices (no prompt without
# that), and points $(PREFIX)/bin/scredmgr at the bundle's executable so
# there is one binary. A later `make install` replaces that symlink with a
# bare copy again; callers that need the LAN should use the bundle path.
install-app: app
	mkdir -p $(APP_DIR) $(PREFIX)/bin
	rm -rf $(APP_DIR)/$(BINARY).app
	ditto $(APP) $(APP_DIR)/$(BINARY).app
	$(LSREGISTER) -f $(APP_DIR)/$(BINARY).app
	ln -sfn $(APP_DIR)/$(BINARY).app/Contents/MacOS/$(BINARY) $(PREFIX)/bin/$(BINARY)
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
