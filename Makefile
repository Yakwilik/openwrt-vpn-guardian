BINARY := vpn-guardian
CMD := ./cmd/vpn-guardian
DIST := dist

.PHONY: test build linux-arm64 linux-amd64 clean

test:
	go test ./...

build:
	go build -trimpath -o $(BINARY) $(CMD)

linux-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(BINARY)-linux-arm64 $(CMD)

linux-amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(DIST)/$(BINARY)-linux-amd64 $(CMD)

clean:
	rm -rf $(DIST) $(BINARY)
