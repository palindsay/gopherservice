.PHONY: all
all: help

.PHONY: help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  deps       Install dependencies"
	@echo "  generate   Generate code from protobuf"
	@echo "  run        Run the server"
	@echo "  tidy       Tidy go.mod"

.PHONY: deps
deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest

.PHONY: generate
generate:
	protoc -I . -I third_party/googleapis \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=. --grpc-gateway_opt=paths=source_relative \
		api/v1/petstore.proto

.PHONY: run
run: generate
	go run ./cmd/server

.PHONY: tidy
tidy:
	go mod tidy

