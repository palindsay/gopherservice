.PHONY: all
all: build-all

.PHONY: help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
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

.PHONY: generate
generate:
	protoc -I . -I third_party/googleapis \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=. --grpc-gateway_opt=paths=source_relative \
		api/v1/petstore.proto

.PHONY: build
build: generate
	go build -o gopherservice ./cmd/server

.PHONY: run
run: build
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
	@echo "Killing any existing gopherservice instances..."
	-killall gopherservice
	@echo "Starting gopherservice in background..."
	./gopherservice &
	@echo "Waiting for server to start..."
	sleep 2
	@echo "Building and running gRPC example..."
	go build -o examples/grpc/grpc-client ./examples/grpc
	./examples/grpc/grpc-client
	@echo "Building and running HTTP example..."
	go build -o examples/http/http-client ./examples/http
	./examples/http/http-client
	@echo "Killing gopherservice..."
	-killall gopherservice
