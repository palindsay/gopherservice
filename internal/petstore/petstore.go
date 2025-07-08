// Copyright 2025 Paddy Lindsay
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package petstore provides a simple in-memory pet store service implementation.
// It demonstrates gRPC service implementation with CRUD operations for pets,
// including telemetry integration and structured logging.
package petstore

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/plindsay/gopherservice/api/v1"
	"github.com/plindsay/gopherservice/pkg/errors"
)

// Service implements the PetStoreService, managing pets and orders in memory.
type Service struct {
	v1.UnimplementedPetStoreServiceServer
	logger *slog.Logger
	pets   map[string]*v1.Pet
	orders map[string]*v1.Order
	mu     sync.RWMutex // Mutex to protect concurrent access to pets and orders maps.
}

// NewService creates and returns a new PetStore service instance.
// It initializes the in-memory storage for pets and orders.
func NewService(logger *slog.Logger) *Service {
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
		return nil, errors.NewValidationError("pet is required").ToGRPCStatus()
	}

	// Validate required fields
	if pet.GetName() == "" {
		return nil, errors.NewValidationError("pet name is required", "Name field cannot be empty").ToGRPCStatus()
	}
	if pet.GetSpecies() == "" {
		return nil, errors.NewValidationError("pet species is required", "Species field cannot be empty").ToGRPCStatus()
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
		return nil, errors.NewConflictError("pet", pet.GetId()).ToGRPCStatus()
	}

	s.pets[pet.GetId()] = pet
	s.logger.Info("created pet",
		slog.String("id", pet.GetId()),
		slog.String("name", pet.GetName()),
		slog.String("species", pet.GetSpecies()),
	)

	return &v1.CreatePetResponse{Pet: pet}, nil
}

// GetPet retrieves a pet by its ID.
// It returns a GetPetResponse containing the requested pet or an error if the pet is not found.
func (s *Service) GetPet(_ context.Context, req *v1.GetPetRequest) (*v1.GetPetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if req.GetId() == "" {
		return nil, errors.NewValidationError("pet ID is required", "ID field cannot be empty").ToGRPCStatus()
	}

	pet, exists := s.pets[req.GetId()]
	if !exists {
		return nil, errors.NewNotFoundError("pet", req.GetId()).ToGRPCStatus()
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
		return nil, errors.NewValidationError("order is required").ToGRPCStatus()
	}

	// Validate required fields
	if order.GetPetId() == "" {
		return nil, errors.NewValidationError("pet ID is required", "PetId field cannot be empty").ToGRPCStatus()
	}
	if order.GetQuantity() <= 0 {
		return nil, errors.NewValidationError("quantity must be greater than 0", "Quantity must be a positive integer").ToGRPCStatus()
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
		return nil, errors.NewConflictError("order", order.GetId()).ToGRPCStatus()
	}

	// Verify the pet exists
	if _, exists := s.pets[order.GetPetId()]; !exists {
		return nil, errors.NewNotFoundError("pet", order.GetPetId()).WithMetadata("context", "pet required for order").ToGRPCStatus()
	}

	s.orders[order.GetId()] = order
	s.logger.Info("placed order",
		slog.String("id", order.GetId()),
		slog.String("pet_id", order.GetPetId()),
		slog.Int("quantity", int(order.GetQuantity())),
	)

	return &v1.PlaceOrderResponse{Order: order}, nil
}

// GetOrder retrieves an order by its ID.
// It returns a GetOrderResponse containing the requested order or an error if the order is not found.
func (s *Service) GetOrder(_ context.Context, req *v1.GetOrderRequest) (*v1.GetOrderResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if req.GetId() == "" {
		return nil, errors.NewValidationError("order ID is required", "ID field cannot be empty").ToGRPCStatus()
	}

	order, exists := s.orders[req.GetId()]
	if !exists {
		return nil, errors.NewNotFoundError("order", req.GetId()).ToGRPCStatus()
	}

	return &v1.GetOrderResponse{Order: order}, nil
}
