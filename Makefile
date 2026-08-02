# Castiel — Makefile
# Build, test, install, and uninstall the Castiel DNS defense system.

VERSION := 0.1.0
BINARY := castiel
APP_NAME := Castiel

PREFIX ?= /usr/local
BIN_DIR := $(PREFIX)/bin
ETC_DIR := $(PREFIX)/etc/castiel
VAR_DIR := $(PREFIX)/var/log/castiel
DATA_DIR := $(PREFIX)/etc/castiel/data

LAUNCH_DAEMON_DIR := /Library/LaunchDaemons
LAUNCH_AGENT_DIR := $(HOME)/Library/LaunchAgents
APP_DIR := /Applications

.PHONY: all build build-app build-linux build-windows build-cross icon test vet clean install uninstall run status logs help

## help: Show available targets
help:
	@echo "Castiel v$(VERSION)"
	@echo ""
	@echo "Build:"
	@echo "  make build       Build the Go daemon binary"
	@echo "  make build-app    Build the macOS SwiftUI app (debug)"
	@echo "  make build-all    Build both daemon and app"
	@echo "  make build-linux  Cross-compile for Linux (amd64 + arm64)"
	@echo "  make build-windows Cross-compile for Windows (amd64 + arm64)"
	@echo "  make build-cross  Cross-compile for all platforms"
	@echo "  make release      Build both in release mode"
	@echo "  make icon         Generate .icns from castiel-logo.png"
	@echo ""
	@echo "Test:"
	@echo "  make test        Run all Go tests"
	@echo "  make vet         Run go vet"
	@echo ""
	@echo "Install/Uninstall:"
	@echo "  make install      Install daemon + app + LaunchDaemon (requires sudo)"
	@echo "  make uninstall    Remove all Castiel components (requires sudo)"
	@echo ""
	@echo "Runtime:"
	@echo "  make run          Run the daemon in foreground"
	@echo "  make status       Check daemon status"
	@echo "  make logs         Tail daemon logs"
	@echo "  make doh-off      Emergency disable DoH"
	@echo "  make doh-on       Re-enable DoH"
	@echo "  make kill-switch  Run kill switch (toggle DoH)"
	@echo "  make restore-dns  Restore DNS to DHCP defaults (emergency)"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean        Remove build artifacts"

## all: Build everything
all: build build-app

## build: Build the Go daemon
build:
	go build -o $(BINARY) .

## build-app: Build the macOS SwiftUI app
build-app:
	cd macos-app && swift build

## icon: Generate .icns from castiel-logo.png
icon:
	@mkdir -p macos-app/Castiel.iconset
	@sips -z 16 16 castiel-logo.png --out macos-app/Castiel.iconset/icon_16x16.png >/dev/null
	@sips -z 32 32 castiel-logo.png --out macos-app/Castiel.iconset/icon_16x16@2x.png >/dev/null
	@sips -z 32 32 castiel-logo.png --out macos-app/Castiel.iconset/icon_32x32.png >/dev/null
	@sips -z 64 64 castiel-logo.png --out macos-app/Castiel.iconset/icon_32x32@2x.png >/dev/null
	@sips -z 128 128 castiel-logo.png --out macos-app/Castiel.iconset/icon_128x128.png >/dev/null
	@sips -z 256 256 castiel-logo.png --out macos-app/Castiel.iconset/icon_128x128@2x.png >/dev/null
	@sips -z 256 256 castiel-logo.png --out macos-app/Castiel.iconset/icon_256x256.png >/dev/null
	@sips -z 512 512 castiel-logo.png --out macos-app/Castiel.iconset/icon_256x256@2x.png >/dev/null
	@sips -z 512 512 castiel-logo.png --out macos-app/Castiel.iconset/icon_512x512.png >/dev/null
	@sips -z 1024 1024 castiel-logo.png --out macos-app/Castiel.iconset/icon_512x512@2x.png >/dev/null
	@iconutil -c icns macos-app/Castiel.iconset -o deploy/Castiel.icns
	@echo "Icon generated: deploy/Castiel.icns"

## build-all: Build daemon and app
build-all: build build-app

## release: Build both in release mode
release:
	go build -ldflags="-s -w" -o $(BINARY) .
	cd macos-app && swift build -c release
	@echo "Release builds complete."
	@echo "  Daemon: $(BINARY)"
	@echo "  App: macos-app/.build/release/$(APP_NAME)"

## build-linux: Cross-compile for Linux
build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o linux_build/castiel .
	@echo "  linux_build/castiel (amd64)"
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o linux_build/castiel-arm64 .
	@echo "  linux_build/castiel-arm64 (arm64)"

## build-windows: Cross-compile for Windows
build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o windows_build/castiel.exe .
	@echo "  windows_build/castiel.exe (amd64)"
	GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o windows_build/castiel-arm64.exe .
	@echo "  windows_build/castiel-arm64.exe (arm64)"

## build-cross: Cross-compile for all platforms
build-cross: build-linux build-windows
	@echo "Cross-compilation complete."
	@echo "  Linux:   linux_build/castiel, linux_build/castiel-arm64"
	@echo "  Windows: windows_build/castiel.exe, windows_build/castiel-arm64.exe"

## test: Run all Go tests
test:
	go test ./... -v -count=1

## vet: Run go vet
vet:
	go vet ./...

## install: Install everything (requires sudo)
install:
	@echo "Installing Castiel v$(VERSION)..."
	@sudo ./deploy/install.sh

## uninstall: Remove everything (requires sudo)
uninstall:
	@echo "Uninstalling Castiel..."
	@sudo ./deploy/uninstall.sh

## run: Run the daemon in foreground
run:
	./$(BINARY) -config config.yaml

## status: Check daemon status
status:
	@launchctl list | grep castiel || echo "Castiel daemon is not loaded"
	@echo ""
	@./doh-killswitch.sh status

## logs: Tail daemon logs
logs:
	@echo "Tailing daemon logs (Ctrl+C to stop)..."
	@tail -f $(VAR_DIR)/daemon.log 2>/dev/null || echo "No log file found. Is the daemon installed?"

## doh-off: Emergency disable DoH
doh-off:
	@./doh-killswitch.sh off

## doh-on: Re-enable DoH
doh-on:
	@./doh-killswitch.sh on

## kill-switch: Toggle DoH
kill-switch:
	@./doh-killswitch.sh toggle

## restore-dns: Restore DNS to DHCP defaults (emergency)
restore-dns:
	@./doh-killswitch.sh restore

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)
	rm -rf macos-app/.build
	rm -f linux_build/castiel linux_build/castiel-arm64
	rm -f windows_build/castiel.exe windows_build/castiel-arm64.exe
	@echo "Clean complete."
