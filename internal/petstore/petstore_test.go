package petstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// TestCreatePet tests the CreatePet method of the PetStore service.
func TestCreatePet(t *testing.T) {
	logger := zap.NewNop()
	s := NewService(logger)
	ctx := context.Background()

	// Test case 1: Successful creation of a pet.
	pet := &v1.Pet{Id: "1", Name: "Fido", Species: "Dog"}
	req := &v1.CreatePetRequest{Pet: pet}
	res, err := s.CreatePet(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, "1", res.GetPet().GetId())
	assert.Equal(t, "Fido", res.GetPet().GetName())
	assert.Equal(t, "Dog", res.GetPet().GetSpecies())
	assert.NotNil(t, res.GetPet().GetBirthDate())

	// Test case 2: Attempt to create a pet with missing required fields, expecting an InvalidArgument error.
	req = &v1.CreatePetRequest{Pet: &v1.Pet{Name: "Buddy"}} // Missing species
	_, err = s.CreatePet(ctx, req)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())

	// Test case 3: Attempt to create a pet that already exists, expecting an AlreadyExists error.
	req = &v1.CreatePetRequest{Pet: pet}
	_, err = s.CreatePet(ctx, req)
	st, _ = status.FromError(err)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

// TestGetPet tests the GetPet method of the PetStore service.
func TestGetPet(t *testing.T) {
	logger := zap.NewNop()
	s := NewService(logger)
	ctx := context.Background()

	// Test case 1: Attempt to retrieve a pet that does not exist, expecting a NotFound error.
	req := &v1.GetPetRequest{Id: "1"}
	_, err := s.GetPet(ctx, req)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())

	// Test case 2: Successful retrieval of an existing pet.
	pet := &v1.Pet{Id: "1", Name: "Fido", Species: "Dog"}
	s.pets[pet.GetId()] = pet // Manually add pet for testing retrieval
	res, err := s.GetPet(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, pet, res.GetPet())
}

// TestPlaceOrder tests the PlaceOrder method of the PetStore service.
func TestPlaceOrder(t *testing.T) {
	logger := zap.NewNop()
	s := NewService(logger)
	ctx := context.Background()

	// Prepare a pet for order placement tests.
	pet := &v1.Pet{Id: "1", Name: "Fido", Species: "Dog"}
	s.pets[pet.GetId()] = pet

	// Test case 1: Successful placement of an order.
	order := &v1.Order{Id: "1", PetId: "1", Quantity: 1}
	req := &v1.PlaceOrderRequest{Order: order}
	res, err := s.PlaceOrder(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, "1", res.GetOrder().GetId())
	assert.Equal(t, "1", res.GetOrder().GetPetId())
	assert.Equal(t, int32(1), res.GetOrder().GetQuantity())
	assert.NotNil(t, res.GetOrder().GetOrderDate())

	// Test case 2: Attempt to place an order with invalid quantity, expecting an InvalidArgument error.
	req = &v1.PlaceOrderRequest{Order: &v1.Order{Id: "2", PetId: "1", Quantity: 0}}
	_, err = s.PlaceOrder(ctx, req)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())

	// Test case 3: Attempt to place an order with an empty pet ID, expecting an InvalidArgument error.
	req = &v1.PlaceOrderRequest{Order: &v1.Order{Id: "3", Quantity: 1}}
	_, err = s.PlaceOrder(ctx, req)
	st, _ = status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())

	// Test case 4: Attempt to place an order that already exists, expecting an AlreadyExists error.
	req = &v1.PlaceOrderRequest{Order: order}
	_, err = s.PlaceOrder(ctx, req)
	st, _ = status.FromError(err)
	assert.Equal(t, codes.AlreadyExists, st.Code())

	// Test case 5: Attempt to place an order for a pet that does not exist, expecting a NotFound error.
	order = &v1.Order{Id: "4", PetId: "2", Quantity: 1}
	req = &v1.PlaceOrderRequest{Order: order}
	_, err = s.PlaceOrder(ctx, req)
	st, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

// TestGetOrder tests the GetOrder method of the PetStore service.
func TestGetOrder(t *testing.T) {
	logger := zap.NewNop()
	s := NewService(logger)
	ctx := context.Background()

	// Test case 1: Attempt to retrieve an order that does not exist, expecting a NotFound error.
	req := &v1.GetOrderRequest{Id: "1"}
	_, err := s.GetOrder(ctx, req)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())

	// Test case 2: Successful retrieval of an existing order.
	order := &v1.Order{Id: "1", PetId: "1", Quantity: 1}
	s.orders[order.GetId()] = order // Manually add order for testing retrieval
	res, err := s.GetOrder(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, order, res.GetOrder())
}
