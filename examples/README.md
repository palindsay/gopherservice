# Gopher Service Examples

This directory contains examples of how to use the gRPC and HTTP REST clients for the PetStore service.

## Running the Examples

These examples demonstrate the full authentication flow (user registration, login, and token refresh) before interacting with the PetStore service. Therefore, you need to ensure the `gopherservice` server is running with the `JWT_SECRET_KEY` environment variable set.

1.  **Start the `gopherservice` server in a separate terminal:**
    ```bash
    JWT_SECRET_KEY="supersecretjwtkey_at_least_32_characters_long" DATABASE_DSN="/tmp/gopherservice.db" OTEL_EXPORTER_OTLP_ENDPOINT="" ./gopherservice
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
