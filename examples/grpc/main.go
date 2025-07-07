package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// main is the entry point for the gRPC example client.
// It demonstrates how to connect to the gRPC server, create a pet, and retrieve it.
func main() {
	// Set up a connection to the gRPC server running on localhost:8080.
	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Create a new Auth client
	authClient := v1.NewAuthServiceClient(conn)

	// Get a token
	token, err := getToken(authClient)
	if err != nil {
		log.Fatalf("could not get token: %v", err)
	}

	// Create a new PetStore client using the established gRPC connection.
	client := v1.NewPetStoreServiceClient(conn)

	// Call the createPet function to add a new pet to the store.
	createPet(client, token)

	// Call the getPet function to retrieve the pet that was just created.
	getPet(client, token)

	// Refresh the token
	newToken, err := refreshToken(authClient, token)
	if err != nil {
		log.Fatalf("could not refresh token: %v", err)
	}

	// Use the new token to get the pet again
	getPet(client, newToken)
}

func getToken(client v1.AuthServiceClient) (*v1.JWTToken, error) {
	log.Println("--- Registering User ---")
	registerReq := &v1.RegisterUserRequest{
		Email:    "test@example.com",
		Password: "password",
		FullName: "Test User",
		Roles:    []string{"user"},
	}
	_, err := client.RegisterUser(context.Background(), registerReq)
	if err != nil {
		log.Printf("could not register user (might already exist): %v", err)
	}

	log.Println("--- Logging In ---")
	loginReq := &v1.LoginRequest{
		Credentials: &v1.UserCredentials{
			Email:    "test@example.com",
			Password: "password",
		},
	}
	loginRes, err := client.Login(context.Background(), loginReq)
	if err != nil {
		return nil, err
	}
	log.Println("Logged in successfully, got token.")
	return loginRes.Token, nil
}

// createPet demonstrates how to create a new pet using the PetStoreServiceClient.
// It takes a PetStoreServiceClient as input and attempts to create a pet with ID "1", Name "Fido", and Species "dog".
// It logs the created pet or a fatal error if the creation fails.
func createPet(client v1.PetStoreServiceClient, token *v1.JWTToken) {
	log.Println("--- CreatePet ---")
	pet := &v1.Pet{
		Id:      "1",
		Name:    "Fido",
		Species: "dog",
	}
	req := &v1.CreatePetRequest{Pet: pet}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token.AccessToken)
	res, err := client.CreatePet(ctx, req)
	if err != nil {
		log.Fatalf("could not create pet: %v", err)
	}
	log.Printf("Created pet: %v", res.GetPet())
}

// getPet demonstrates how to retrieve a pet by its ID using the PetStoreServiceClient.
// It takes a PetStoreServiceClient as input and attempts to retrieve the pet with ID "1".
// It logs the retrieved pet or a fatal error if the retrieval fails.
func getPet(client v1.PetStoreServiceClient, token *v1.JWTToken) {
	log.Println("--- GetPet ---")
	req := &v1.GetPetRequest{Id: "1"}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token.AccessToken)
	res, err := client.GetPet(ctx, req)
	if err != nil {
		log.Fatalf("could not get pet: %v", err)
	}
	log.Printf("Got pet: %v", res.GetPet())
}

func refreshToken(client v1.AuthServiceClient, token *v1.JWTToken) (*v1.JWTToken, error) {
	log.Println("--- Refreshing Token ---")
	refreshReq := &v1.RefreshTokenRequest{RefreshToken: token.RefreshToken}
	refreshRes, err := client.RefreshToken(context.Background(), refreshReq)
	if err != nil {
		return nil, err
	}
	log.Println("Token refreshed successfully.")
	return refreshRes.Token, nil
}
