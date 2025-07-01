//go:build tools

// Package tools is used to track Go tool dependencies.
// These dependencies are not part of the main application build
// but are required for development tasks like code generation.
package tools

import (
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway"
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)
