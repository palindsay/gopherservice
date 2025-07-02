package petstore

import (
	"context"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// Service implements the PetStoreService, managing pets and orders in memory.
type Service struct {
	v1.UnimplementedPetStoreServiceServer
	logger *zap.Logger
	pets   map[string]*v1.Pet
	orders map[string]*v1.Order
	mu     sync.RWMutex // Mutex to protect concurrent access to pets and orders maps.
}

// NewService creates and returns a new PetStore service instance.
// It initializes the in-memory storage for pets and orders.
func NewService(logger *zap.Logger) *Service {
	return &Service{
		logger: logger,
		pets:   make(map[string]*v1.Pet),
		orders: make(map[string]*v1.Order),
	}
}

// CreatePet creates a new pet in the pet store.
// It auto-generates an ID if not provided and validates required fields.
// It returns a CreatePetResponse containing the created pet or an error if validation fails.
func (s *Service) CreatePet(_ context.Context, req *v1.CreatePetRequest) (*v1.CreatePetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pet := req.GetPet()
	if pet == nil {
		return nil, status.Error(codes.InvalidArgument, "pet is required")
	}

	// Validate required fields
	if pet.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "pet name is required")
	}
	if pet.GetSpecies() == "" {
		return nil, status.Error(codes.InvalidArgument, "pet species is required")
	}

	// Auto-generate ID if not provided
	if pet.GetId() == "" {
		pet.Id = uuid.New().String()
	}

	// Set birth date if not provided
	if pet.BirthDate == nil {
		pet.BirthDate = timestamppb.Now()
	}

	// Check if pet with this ID already exists
	if _, exists := s.pets[pet.GetId()]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "pet with ID %q already exists", pet.GetId())
	}

	s.pets[pet.GetId()] = pet
	s.logger.Info("created pet",
		zap.String("id", pet.GetId()),
		zap.String("name", pet.GetName()),
		zap.String("species", pet.GetSpecies()),
	)

	return &v1.CreatePetResponse{Pet: pet}, nil
}

// GetPet retrieves a pet by its ID.
// It returns a GetPetResponse containing the requested pet or an error if the pet is not found.
func (s *Service) GetPet(_ context.Context, req *v1.GetPetRequest) (*v1.GetPetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "pet ID is required")
	}

	pet, exists := s.pets[req.GetId()]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "pet with ID %q not found", req.GetId())
	}

	return &v1.GetPetResponse{Pet: pet}, nil
}

// PlaceOrder places a new order for a pet.
// It auto-generates an ID if not provided and validates required fields.
// It returns a PlaceOrderResponse containing the placed order or an error if validation fails.
func (s *Service) PlaceOrder(_ context.Context, req *v1.PlaceOrderRequest) (*v1.PlaceOrderResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	order := req.GetOrder()
	if order == nil {
		return nil, status.Error(codes.InvalidArgument, "order is required")
	}

	// Validate required fields
	if order.GetPetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "pet ID is required")
	}
	if order.GetQuantity() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "quantity must be greater than 0")
	}

	// Auto-generate ID if not provided
	if order.GetId() == "" {
		order.Id = uuid.New().String()
	}

	// Set order date if not provided
	if order.OrderDate == nil {
		order.OrderDate = timestamppb.Now()
	}

	// Check if order with this ID already exists
	if _, exists := s.orders[order.GetId()]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "order with ID %q already exists", order.GetId())
	}

	// Verify the pet exists
	if _, exists := s.pets[order.GetPetId()]; !exists {
		return nil, status.Errorf(codes.NotFound, "pet with ID %q not found", order.GetPetId())
	}

	s.orders[order.GetId()] = order
	s.logger.Info("placed order",
		zap.String("id", order.GetId()),
		zap.String("pet_id", order.GetPetId()),
		zap.Int32("quantity", order.GetQuantity()),
	)

	return &v1.PlaceOrderResponse{Order: order}, nil
}

// GetOrder retrieves an order by its ID.
// It returns a GetOrderResponse containing the requested order or an error if the order is not found.
func (s *Service) GetOrder(_ context.Context, req *v1.GetOrderRequest) (*v1.GetOrderResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "order ID is required")
	}

	order, exists := s.orders[req.GetId()]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "order with ID %q not found", req.GetId())
	}

	return &v1.GetOrderResponse{Order: order}, nil
}
