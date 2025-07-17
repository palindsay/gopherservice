# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gopherservice is a production-ready Go microservice implementing a Pet Store API with both gRPC (port 8080) and REST/HTTP (port 8081) endpoints. It demonstrates modern Go microservice patterns including JWT authentication, OpenTelemetry observability, and clean architecture.

## Essential Commands

### Development Workflow
```bash
# Initial setup - install dev dependencies
make deps

# Generate Go code from .proto files (required after proto changes)
make generate

# Build the server
make build

# Run tests with coverage
make test

# Run linter
make lint

# Complete build pipeline (deps → generate → build → test → lint)
make build-all

# Run the server locally
JWT_SECRET_KEY="your-secret-key" make run

# Run with Docker Compose (includes OpenTelemetry collector)
docker-compose up --build
```

### Testing
```bash
# Run all tests with coverage
make test

# Run tests with race detection
go test -race ./...

# Run a specific test
go test -v -run TestFunctionName ./internal/petstore
```

## Architecture

### Service Structure
- **api/v1/**: Protocol buffer definitions (auth.proto, petstore.proto) - the source of truth for APIs
- **internal/**: Private application code organized by domain (auth, petstore, config, database)
- **pkg/**: Public packages for auth utilities, custom errors, and telemetry
- **cmd/server/**: Main entry point that wires everything together

### Key Design Patterns
1. **API-First**: All APIs defined in protobuf, generating both gRPC and REST/HTTP handlers
2. **Repository Pattern**: Storage interfaces in `internal/*/repository.go` with implementations
3. **Service Layer**: Business logic in `internal/*/service.go` 
4. **Clean Architecture**: Dependencies flow inward - handlers → services → repositories

### Authentication Flow
- JWT-based with access tokens (15 min) and refresh tokens (7 days)
- Tokens generated using golang-jwt/jwt v5
- Authentication enforced via gRPC interceptors and HTTP middleware
- bcrypt for password hashing

### Environment Variables
```bash
GRPC_PORT=8080                  # gRPC server port
HTTP_PORT=8081                  # HTTP/REST server port
JWT_SECRET_KEY="secret"         # Required for JWT signing
DATABASE_DSN="sqlite://file.db" # Database connection
OTEL_EXPORTER_OTLP_ENDPOINT=""  # OpenTelemetry collector
```

## Code Generation

After modifying .proto files:
```bash
make generate
```

This regenerates:
- `api/v1/*.pb.go` - Protocol buffer messages
- `api/v1/*_grpc.pb.go` - gRPC service interfaces
- `api/v1/*.pb.gw.go` - REST/HTTP gateway handlers

## Important Patterns

### Error Handling
- Use custom errors from `pkg/errors` package
- Return gRPC status errors with appropriate codes
- Log errors with context using structured logging

### Testing
- Unit tests alongside implementation files (*_test.go)
- Use table-driven tests for comprehensive coverage
- Mock external dependencies (database, auth)

### Observability
- Tracing: All requests automatically traced via OpenTelemetry
- Logging: Structured JSON logs with slog
- Metrics: Exponential histograms for latency tracking

## Running Examples

```bash
# Terminal 1: Start server
JWT_SECRET_KEY="test" make run

# Terminal 2: Run example clients
make run-examples
```

Examples demonstrate:
- Authentication flow (login → access token → API calls)
- CRUD operations for pets
- Both gRPC and HTTP/REST clients