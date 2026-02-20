.PHONY: all
all: build-all

.PHONY: help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  install-deps Install all system and Go dependencies"
	@echo "  install-protoc Install Protocol Buffers compiler"
	@echo "  clean      Remove build artifacts"
	@echo "  deps       Install/update Go tool dependencies"
	@echo "  generate   Generate Go code from protobuf definitions"
	@echo "  build      Build the main server executable"
	@echo "  run        Run the server"
	@echo "  test       Run all Go tests with coverage"
	@echo "  lint       Run golangci-lint on the codebase"
	@echo "  tidy       Tidy go.mod and go.sum files"
	@echo "  build-all  Build, test, and lint the entire project"
	@echo "  run-examples Build and run gRPC and HTTP examples"

.PHONY: install-protoc
install-protoc:
	@echo "Installing Protocol Buffers compiler..."
	@if command -v protoc >/dev/null 2>&1; then \
		echo "protoc is already installed: $$(protoc --version)"; \
	else \
		echo "protoc not found. Please install it using one of these methods:"; \
		echo ""; \
		echo "On macOS:"; \
		echo "  brew install protobuf"; \
		echo ""; \
		echo "On Ubuntu/Debian:"; \
		echo "  sudo apt-get update && sudo apt-get install -y protobuf-compiler"; \
		echo ""; \
		echo "On Fedora:"; \
		echo "  sudo dnf install protobuf-compiler"; \
		echo ""; \
		echo "Or download from: https://github.com/protocolbuffers/protobuf/releases"; \
		exit 1; \
	fi

.PHONY: install-deps
install-deps: install-protoc deps googleapis
	@echo "All dependencies installed successfully!"

.PHONY: googleapis
googleapis:
	@if [ ! -d "third_party/googleapis" ]; then \
		echo "Downloading googleapis..."; \
		mkdir -p third_party; \
		git clone --depth 1 https://github.com/googleapis/googleapis.git third_party/googleapis; \
	fi

.PHONY: clean
clean:
	rm -f gopherservice
	rm -f examples/grpc/grpc-client
	rm -f examples/http/http-client

.PHONY: deps
deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go mod download

.PHONY: generate
generate: googleapis
	protoc -I . -I third_party/googleapis -I /usr/local/include \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=. --grpc-gateway_opt=paths=source_relative \
		api/v1/petstore.proto api/v1/auth.proto

.PHONY: build
build: generate
	go build -o gopherservice ./cmd/server

.PHONY: run
run: build
	@if [ -z "$(JWT_SECRET_KEY)" ]; then \
		echo "ERROR: JWT_SECRET_KEY environment variable is not set."; \
		echo "Please set it with a value of at least 32 characters:"; \
		echo "  export JWT_SECRET_KEY=\"your-super-secret-jwt-key-that-is-at-least-32-characters-long\""; \
		echo "Or run with:"; \
		echo "  JWT_SECRET_KEY=\"your-super-secret-jwt-key-that-is-at-least-32-characters-long\" make run"; \
		exit 1; \
	fi
	./gopherservice

.PHONY: test
test:
	go test -cover ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: build-all
build-all: deps generate build test lint

.PHONY: run-examples
run-examples:
	@echo "Building gopherservice..."
	go build -o gopherservice ./cmd/server
	@echo "Starting gopherservice..."
	DATABASE_DSN=":memory:" OTEL_EXPORTER_OTLP_ENDPOINT="" JWT_SECRET_KEY="example-jwt-secret-key-that-is-at-least-32-characters-long" ./gopherservice &
	@echo "Building and running gRPC example..."
	go build -o examples/grpc/grpc-client ./examples/grpc
	./examples/grpc/grpc-client
	@echo "Building and running HTTP example..."
	go build -o examples/http/http-client ./examples/http
	./examples/http/http-client
	@echo "Killing gopherservice..."
	-killall gopherservice
