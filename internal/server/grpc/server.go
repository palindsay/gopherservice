package grpc

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	v1 "github.com/plindsay/gopherservice/api/v1"
	"github.com/plindsay/gopherservice/internal/petstore"
)

// New creates a new gRPC server.
func New(ctx context.Context, logger *zap.Logger, port int, petStoreService *petstore.Service) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen: %w", err)
	}

	s := grpc.NewServer()
	v1.RegisterPetStoreServiceServer(s, petStoreService)

	return s, lis, nil
}
