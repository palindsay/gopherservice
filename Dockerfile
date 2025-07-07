# syntax=docker/dockerfile:1

# Stage 1: Builder
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application
RUN GOOS=linux go build -o /gopherservice ./cmd/server

# Stage 2: Final image
FROM alpine:latest

# Install ca-certificates and tzdata for timezone support
RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the working directory
WORKDIR /app

# Copy the built executable from the builder stage
COPY --from=builder /gopherservice /app/gopherservice

# Set permissions for the non-root user
RUN chown appuser:appgroup /app/gopherservice

# Use the non-root user
USER appuser

# Expose ports
EXPOSE 8080 8081

# Command to run the application
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD wget -q -O /dev/null http://localhost:8081/grpc.health.v1.Health/Check || exit 1

ENTRYPOINT ["/app/gopherservice"]
