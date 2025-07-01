# Gopher Service

This is a skeleton for a modern Go API service.

## Features

*   Go 1.24+
*   gRPC
*   gRPC-Gateway for REST
*   Protobuf
*   OpenTelemetry
*   `zap` for structured logging

## Setup

1.  **Install dependencies:**

    ```bash
    make deps
    ```

2.  **Generate code from protobuf:**

    ```bash
    make generate
    ```

3.  **Tidy go.mod:**

    ```bash
    make tidy
    ```

## Running the service

```bash
make run
```

This will start the gRPC server on port 8080 and the HTTP server on port 8081.
