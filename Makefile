BINARY := vpn-guardian
CMD := ./cmd/vpn-guardian
DIST := dist
WEBUI := webui

.PHONY: test check build ui-install ui-check ui-build linux-arm64 linux-amd64 clean

test:
	go test ./...

check: ui-check test
	go vet ./...

ui-install:
	cd $(WEBUI) && npm ci

ui-check:
	cd $(WEBUI) && npm run check

ui-build:
	cd $(WEBUI) && npm run build

build: ui-build
	go build -trimpath -o $(BINARY) $(CMD)

linux-arm64: ui-build
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(BINARY)-linux-arm64 $(CMD)

linux-amd64: ui-build
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(BINARY)-linux-amd64 $(CMD)

clean:
	rm -rf $(DIST) $(BINARY) $(WEBUI)/node_modules
