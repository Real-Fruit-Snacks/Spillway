.PHONY: all listener build-linux-amd64 build-linux-arm64 build-windows-amd64 build-darwin-amd64 build-darwin-arm64 build-all compress clean test fmt vet

BINARY_NAME=spillway
BUILD_DIR=bin
MODULE=github.com/Real-Fruit-Snacks/Spillway

# Default listener build
all: listener

listener:
	@mkdir -p $(BUILD_DIR)
	go build -trimpath -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/spillway

# Agent cross-compilation targets (require ldflags, use build.sh instead)
build-linux-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags agent -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-agent-linux-amd64 ./cmd/spillway

build-linux-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags agent -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-agent-linux-arm64 ./cmd/spillway

build-windows-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags agent -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-agent-windows-amd64.exe ./cmd/spillway

build-darwin-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -tags agent -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-agent-darwin-amd64 ./cmd/spillway

build-darwin-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -tags agent -trimpath -o $(BUILD_DIR)/$(BINARY_NAME)-agent-darwin-arm64 ./cmd/spillway

build-all: build-linux-amd64 build-linux-arm64 build-windows-amd64 build-darwin-amd64 build-darwin-arm64

compress:
	@which upx > /dev/null 2>&1 || (echo "UPX not found"; exit 1)
	@for f in $(BUILD_DIR)/$(BINARY_NAME)-agent-*; do \
		if [ -f "$$f" ] && ! echo "$$f" | grep -q '.exe$$'; then \
			upx --best "$$f" || true; \
		fi; \
	done

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...
	go vet -tags agent ./...
