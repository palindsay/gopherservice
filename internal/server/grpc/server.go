package grpc

import (
	"context"
	"fmt"
	"net"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	v1 "github.com/plindsay/gopherservice/api/v1"
	"github.com/plindsay/gopherservice/internal/petstore"
)

// New creates a new gRPC server instance and a listener.
// It takes a context, a logger, the port to listen on, and the PetStore service implementation.
// It returns the gRPC server, the network listener, and an error if the listener cannot be created.
func New(_ context.Context, _ *zap.Logger, port int, petStoreService *petstore.Service) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen: %w", err)
	}

	s := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()))
	v1.RegisterPetStoreServiceServer(s, petStoreService)

	return s, lis, nil
}
