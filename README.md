# Gopher Service

A production-ready Go microservice implementing a Pet Store API with modern observability and best practices.

## Features

### Core Technology Stack
*   **Go 1.24+** - Latest Go version with modern language features
*   **gRPC** - High-performance RPC framework with HTTP/2
*   **gRPC-Gateway** - Automatic REST API generation from gRPC definitions
*   **Protocol Buffers** - Efficient serialization and API-first design
*   **OpenTelemetry** - Distributed tracing and metrics with exponential histograms
*   **Structured Logging** - High-performance structured logging using `log/slog`

### Authentication & Authorization
*   **JWT-based Authentication**: Secure token generation and validation.
*   **Refresh Tokens**: Mechanism for obtaining new access tokens without re-authentication.
*   **gRPC Interceptors**: Centralized authentication and role-based authorization for gRPC endpoints.
*   **Password Hashing**: Secure password storage using bcrypt.


### Production Features
*   **Health Checks** - Standard gRPC health check protocol
*   **Request Logging** - Structured logging with request/response details
*   **Auto-ID Generation** - UUIDs automatically generated when not provided
*   **Input Validation** - Comprehensive validation with proper error codes
*   **Graceful Shutdown** - Clean service shutdown on interrupt signals
*   **Keep-Alive Settings** - Production-ready connection management
*   **gRPC Reflection** - Service discovery for development and debugging
*   **Thread Safety** - Concurrent-safe operations with proper mutex usage

### Development & Deployment
*   **Docker & Docker Compose** - Containerized deployment with observability stack
*   **Code Generation** - Automated protobuf code generation
*   **Testing** - Comprehensive unit tests with race detection
*   **Linting** - Code quality enforcement with golangci-lint

## Quick Start

### Prerequisites
- Go 1.24 or later
- Protocol Buffers compiler (`protoc`)
- Docker and Docker Compose (optional)

### Initial Setup

1.  **Clone and enter the project:**
    ```bash
    git clone <repo-url>
    cd gopherservice
    ```

2.  **Install dependencies and generate code:**
    ```bash
    make deps     # Install protoc plugins and tools
    make generate # Generate Go code from .proto files
    make tidy     # Clean up Go modules
    ```

3.  **Build and test:**
    ```bash
    make build    # Build the service
    make test     # Run unit tests
    make lint     # Run code quality checks
    ```

4.  **Complete build pipeline:**
    ```bash
    make build-all  # Run deps, generate, build, test, and lint
    ```

## Building the Service

### Build the main service:
```bash
make build
```

### Build example clients:
```bash
go build -o examples/grpc/grpc-client ./examples/grpc
go build -o examples/http/http-client ./examples/http
```

## Running the Service

### Native Execution

Start the service locally:
```bash
make run
```

**Service Endpoints:**
- **gRPC Server**: `localhost:8080`
- **HTTP/REST API**: `localhost:8081`

### With Docker Compose (Recommended)

Run with full observability stack:
```bash
docker-compose up --build
```

**Available Services:**
- **gRPC Server**: `localhost:8080`
- **HTTP/REST API**: `localhost:8081`
- **OpenTelemetry Collector**: `localhost:4317`

### Environment Variables

Configure the service with these environment variables:
```bash
export GRPC_PORT=8080          # gRPC server port
export HTTP_PORT=8081          # HTTP gateway port
export JWT_SECRET_KEY="your-secret-key" # Secret key for JWT signing (REQUIRED)
```

## Testing

### Unit Tests
Run all tests with coverage:
```bash
make test
```

### Race Detection
Test for race conditions:
```bash
go test -race ./...
```

### Code Quality
Run linting and formatting checks:
```bash
make lint
```

### Complete Verification
Run the entire build and test pipeline:
```bash
make build-all
```

## API Usage Examples

### Running Examples

To run the gRPC and HTTP examples, you need to start the `gopherservice` server manually in a separate terminal, and then run the client examples.

1.  **Start the `gopherservice` server in a separate terminal:**
    ```bash
    JWT_SECRET_KEY="supersecretjwtkey" DATABASE_DSN="/tmp/gopherservice.db" OTEL_EXPORTER_OTLP_ENDPOINT="" ./gopherservice
    ```
    (Keep this terminal open while running the client examples.)

2.  **In a new terminal, run the gRPC client example:**
    ```bash
    go run ./examples/grpc
    ```

3.  **In another new terminal, run the HTTP client example:**
    ```bash
    go run ./examples/http
    ```

4.  **To stop the `gopherservice` server, press `Ctrl+C` in the terminal where it's running.**

### API Endpoints

#### Authentication (HTTP/REST)

**Register a User:**
```bash
curl -X POST http://localhost:8081/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "password123",
    "full_name": "Test User",
    "roles": ["user"]
  }'
```

**Login and Get Token:**
```bash
curl -X POST http://localhost:8081/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "credentials": {
      "email": "testuser@example.com",
      "password": "password123"
    }
  }'
# Save the access_token and refresh_token from the response
```

**Refresh Token:**
```bash
curl -X POST http://localhost:8081/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
# Get a new access_token
```

#### Authenticated PetStore API (HTTP/REST)

**Create a Pet (requires authentication):**
```bash
curl -X POST http://localhost:8081/v1/pets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "pet": {
      "name": "Buddy",
      "species": "Dog"
    }
  }'
```

**Get a Pet (requires authentication):**
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8081/v1/pets/{pet-id}
```

**Place an Order (requires authentication):**
```bash
curl -X POST http://localhost:8081/v1/orders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "order": {
      "petId": "{pet-id}",
      "quantity": 1
    }
  }'
```

**Get an Order (requires authentication):**
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8081/v1/orders/{order-id}
```

#### gRPC API

Use tools like `grpcurl` or `evans` to interact with the gRPC API. For authenticated calls, you'll need to pass the JWT access token in the metadata.

**Login and Get Token (gRPC):**
```bash
grpcurl -plaintext -d '{
  "credentials": {
    "email": "testuser@example.com",
    "password": "password123"
  }
}' localhost:8080 v1.AuthService/Login
# Save the access_token and refresh_token from the response
```

**Create a Pet (requires authentication via gRPC):**
```bash
grpcurl -plaintext \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "pet": {
      "name": "Buddy",
      "species": "Dog"
    }
  }' localhost:8080 v1.PetStoreService/CreatePet
```

**Health check:**
```bash
grpcurl -plaintext localhost:8080 grpc.health.v1.Health/Check
```

**Create a pet (old example, now requires auth):**
```bash
grpcurl -plaintext -d '{
  "pet": {
    "name": "Buddy",
    "species": "Dog"
  }
}' localhost:8080 v1.PetStoreService/CreatePet
```

## Architecture

### Service Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   HTTP Client   │    │    gRPC Client   │    │  Health Checks  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ gRPC-Gateway    │    │   gRPC Server    │    │ gRPC Reflection │
│ (REST Proxy)    │    │                  │    │                 │
│ Port: 8081      │    │   Port: 8080     │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                                  ▼
                       ┌──────────────────┐
                       │  PetStore Service │
                       │  (Business Logic) │
                       └──────────────────┘
                                  │
                                  ▼
                       ┌──────────────────┐
                       │   In-Memory      │
                       │   Storage        │
                       │ (Thread-Safe)    │
                       └──────────────────┘
```

### Observability Stack
- **Traces**: OpenTelemetry → OTLP Collector
- **Metrics**: Exponential histograms for latency/duration
- **Logs**: Structured JSON with `log/slog`
- **Health**: Standard gRPC health checks

### Key Design Patterns
- **API-First**: Protocol buffers define the contract
- **Clean Architecture**: Clear separation of concerns
- **Dual Protocol**: Single implementation serves gRPC + REST
- **Thread Safety**: Concurrent operations with proper synchronization

## Observability & Monitoring

### OpenTelemetry Integration
The service includes comprehensive observability:

**Tracing:**
- Automatic gRPC request tracing
- Distributed trace propagation
- Request/response logging with correlation IDs

**Metrics:**
- Exponential histograms for key service metrics
- gRPC server duration, latency, errors, and payload size
- Delta temporality for efficient metric collection

**Health Checks:**
```bash
# Check overall service health
grpcurl -plaintext localhost:8080 grpc.health.v1.Health/Check

# Check specific service health  
grpcurl -plaintext -d '{"service":"v1.PetStoreService"}' \
  localhost:8080 grpc.health.v1.Health/Check
```

### Logging
Structured JSON logging with:
- Request method and duration
- gRPC status codes
- Error details and stack traces
- Business operation context (pet/order IDs)

## Development

### Project Structure
```
gopherservice/
├── api/v1/                 # Protocol buffer definitions
├── cmd/server/             # Main application entry point
├── internal/               # Private application code
│   ├── config/            # Configuration loading
│   ├── log/               # Logger initialization  
│   ├── petstore/          # Business logic implementation
│   └── server/grpc/       # gRPC server setup
├── pkg/telemetry/         # Shared telemetry utilities
├── examples/              # Client examples
│   ├── grpc/             # gRPC client example
│   └── http/             # HTTP client example
└── third_party/           # External dependencies
```

### Code Generation
Protocol buffer code is automatically generated:
```bash
make generate  # Generates Go code from .proto files
```

Generated files:
- `api/v1/petstore.pb.go` - Protocol buffer types
- `api/v1/petstore_grpc.pb.go` - gRPC service definitions  
- `api/v1/petstore.pb.gw.go` - gRPC-Gateway REST mappings

### Make Targets
| Command | Description |
|---------|-------------|
| `make deps` | Install development dependencies |
| `make generate` | Generate code from proto files |
| `make build` | Build the service executable |
| `make test` | Run unit tests with coverage |
| `make lint` | Run code quality checks |
| `make run` | Start the service locally |
| `make run-examples` | Build and run example clients |
| `make build-all` | Complete build pipeline |
| `make clean` | Remove build artifacts |
| `make tidy` | Clean up Go modules |

### Contributing
1. Make changes to `.proto` files for API modifications
2. Run `make generate` to update generated code
3. Implement business logic in `internal/petstore/`
4. Add tests and run `make test`
5. Verify with `make build-all`

## Production Deployment

### Docker
Build and run with Docker:
```bash
docker build -t gopherservice .
docker run -p 8080:8080 -p 8081:8081 gopherservice
```

### Docker Compose
Full stack with observability:
```bash
docker-compose up -d
```

This includes:
- Gopherservice (gRPC + HTTP)
- OpenTelemetry Collector
- Example telemetry configuration

### Kubernetes
Kubernetes configurations are provided in the `kubernetes/` directory.

**Generated Files:**
- `kubernetes/otel-collector-configmap.yaml`: ConfigMap for OpenTelemetry collector configuration.
- `kubernetes/otel-collector-deployment-service.yaml`: Deployment and Service for the OpenTelemetry collector.
- `kubernetes/gopherservice-deployment-service.yaml`: Deployment and Service for the `gopherservice` application.

**Deployment Steps:**
1.  **Ensure your Docker image `gopherservice:latest` is available in your Kubernetes cluster's image registry.** If you're using a local Kubernetes (like Minikube or Kind), you might need to load the image into its daemon:
    ```bash
    docker build -t gopherservice .
    # If using Minikube:
    minikube image load gopherservice:latest
    # If using Kind:
    kind load docker-image gopherservice:latest
    ```
2.  **Apply the configurations:**
    ```bash
    kubectl apply -f kubernetes/otel-collector-configmap.yaml
    kubectl apply -f kubernetes/otel-collector-deployment-service.yaml
    kubectl apply -f kubernetes/gopherservice-deployment-service.yaml
    ```
3.  **Check the status of your deployments:**
    ```bash
    kubectl get pods
    kubectl get services
    ```

**Further Considerations for Kubernetes:**
-   **Ingress**: For external access to your HTTP/REST API.
-   **Secrets**: For sensitive information like `JWT_SECRET_KEY` instead of hardcoding them or passing them as environment variables directly in the Deployment YAML.
-   **Resource Limits/Requests**: To define CPU and memory limits for your pods.
-   **Horizontal Pod Autoscaler (HPA)**: For automatic scaling based on metrics.
-   **Persistent Volume Claims (PVCs)**: If your `gopherservice` needs persistent storage (currently it uses a file-based SQLite in `/tmp`, which is ephemeral in a container).

### Configuration
Service configuration via `config.yaml`:
```yaml
telemetry:
  serviceName: "gopherservice"
  endpoint: "localhost:4317"
```

Environment variable overrides:
- `GRPC_PORT`: gRPC server port (default: 8080)
- `HTTP_PORT`: HTTP gateway port (default: 8081)

## State-of-the-Art Features

This project exemplifies Go microservice best practices with:

### Modern Go Patterns
- **Go 1.24+**: Latest language features and performance improvements
- **Clean Architecture**: Clear separation with `internal/` and `pkg/` structure
- **Interface-Based Design**: Dependency injection ready architecture
- **Thread Safety**: Proper mutex usage for concurrent operations
- **Context Propagation**: Request-scoped contexts throughout the call chain

### gRPC Excellence
- **Production-Ready Server**: Keepalive, health checks, and graceful shutdown
- **OpenTelemetry Integration**: Automatic tracing and metrics collection
- **gRPC-Gateway**: Seamless HTTP/REST API from protobuf definitions
- **Service Reflection**: Development and debugging support
- **Error Handling**: Proper gRPC status codes and error propagation

### Observability Standards
- **Distributed Tracing**: OpenTelemetry with OTLP export
- **Metrics**: Exponential histograms for performance monitoring
- **Structured Logging**: High-performance `log/slog` with correlation
- **Health Checks**: Standard gRPC health check protocol

### Development Experience
- **Code Generation**: Automated protobuf compilation
- **Comprehensive Testing**: Unit tests with 87%+ coverage
- **Quality Gates**: golangci-lint integration
- **Docker Support**: Multi-stage builds and compose orchestration
- **Example Clients**: Working gRPC and HTTP examples
## License

Copyright 2025 Phillip Lindsay

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
