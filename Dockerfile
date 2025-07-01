# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /gopherservice ./cmd/server

FROM alpine:latest

WORKDIR /

COPY --from=builder /gopherservice /gopherservice

EXPOSE 8080 8081

ENTRYPOINT ["/gopherservice"]
