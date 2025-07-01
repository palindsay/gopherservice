# Gopher Service

This is a skeleton for a modern Go API service.

## Features

*   Go 1.24+
*   gRPC
*   gRPC-Gateway for REST
*   Protobuf
*   OpenTelemetry
*   `zap` for structured logging
*   Docker and Docker Compose support

## Setup

1.  **Install/Update Dependencies:**

    ```bash
    make deps
    ```

2.  **Generate Code:**

    ```bash
    make generate
    ```

3.  **Tidy Go Modules:**

    ```bash
    make tidy
    ```

## Building the Service

To build the service executable:

```bash
make build
```

This will create an executable named `gopherservice` in the project root directory.

## Running the Service

### Natively

To run the service locally:

```bash
make run
```

This will start the gRPC server on port 8080 and the HTTP server (gRPC-Gateway) on port 8081.

### With Docker Compose

To run the service using Docker Compose:

```bash
docker-compose up --build
```

This will start the gRPC server on port 8080, the HTTP server on port 8081, and an OpenTelemetry collector on port 4317.

## Testing

To run all unit tests and check code coverage:

```bash
make test
```

To run the linter:

```bash
make lint
```

## Running Examples

To build and run the gRPC and HTTP example clients:

```bash
make run-examples
```

This will execute both the gRPC and HTTP example clients, demonstrating basic interactions with the service.