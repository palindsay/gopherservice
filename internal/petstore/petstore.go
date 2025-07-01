package petstore

import (
	"context"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// Service implements the PetStoreService.
type Service struct {
	v1.UnimplementedPetStoreServiceServer
	logger *zap.Logger
	pets   map[string]*v1.Pet
	orders map[string]*v1.Order
	mu     sync.RWMutex
}

// NewService creates a new PetStore service.
func NewService(logger *zap.Logger) *Service {
	return &Service{
		logger: logger,
		pets:   make(map[string]*v1.Pet),
		orders: make(map[string]*v1.Order),
	}
}

// CreatePet creates a new pet.
func (s *Service) CreatePet(ctx context.Context, req *v1.CreatePetRequest) (*v1.CreatePetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pet := req.GetPet()
	if pet.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "pet ID is required")
	}

	if _, exists := s.pets[pet.GetId()]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "pet with ID %q already exists", pet.GetId())
	}

	s.pets[pet.GetId()] = pet
	s.logger.Info("created pet", zap.String("id", pet.GetId()))

	return &v1.CreatePetResponse{Pet: pet}, nil
}

// GetPet gets a pet by its ID.
func (s *Service) GetPet(ctx context.Context, req *v1.GetPetRequest) (*v1.GetPetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pet, exists := s.pets[req.GetId()]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "pet with ID %q not found", req.GetId())
	}

	return &v1.GetPetResponse{Pet: pet}, nil
}

// PlaceOrder places an order for a pet.
func (s *Service) PlaceOrder(ctx context.Context, req *v1.PlaceOrderRequest) (*v1.PlaceOrderResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order := req.GetOrder()
	if order.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "order ID is required")
	}
	if order.GetPetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "pet ID is required")
	}

	if _, exists := s.orders[order.GetId()]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "order with ID %q already exists", order.GetId())
	}

	if _, exists := s.pets[order.GetPetId()]; !exists {
		return nil, status.Errorf(codes.NotFound, "pet with ID %q not found", order.GetPetId())
	}

	s.orders[order.GetId()] = order
	s.logger.Info("placed order", zap.String("id", order.GetId()))

	return &v1.PlaceOrderResponse{Order: order}, nil
}

// GetOrder gets an order by its ID.
func (s *Service) GetOrder(ctx context.Context, req *v1.GetOrderRequest) (*v1.GetOrderResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	order, exists := s.orders[req.GetId()]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "order with ID %q not found", req.GetId())
	}

	return &v1.GetOrderResponse{Order: order}, nil
}
