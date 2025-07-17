// Copyright 2025 Phillip Lindsay
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

// Package main provides an example gRPC client for the gopherservice.
// It demonstrates how to connect to the gRPC server, authenticate with the auth service,
// and perform operations on the pet store service including creating and retrieving pets.
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// main is the entry point for the gRPC example client.
// It demonstrates how to connect to the gRPC server, create a pet, and retrieve it.
func main() {
	// Define command-line flags
	var (
		server = flag.String("server", getEnv("GRPC_SERVER", "localhost:8080"), "gRPC server address")
		help   = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	log.Printf("Connecting to gRPC server at %s", *server)

	// Set up a connection to the gRPC server.
	conn, err := grpc.NewClient(*server, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

// getToken registers a test user and logs in to obtain a JWT token.
// It first attempts to register a user and then logs in to get the authentication token.
// Returns the JWT token containing both access and refresh tokens.
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

// refreshToken uses a refresh token to obtain a new access token.
// It takes the current JWT token and exchanges the refresh token for a new access token.
// Returns the new JWT token with updated access and refresh tokens.
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

// getEnv returns the value of an environment variable or a default value if not set.
// It provides a simple way to configure the client through environment variables.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// printUsage prints usage information for the gRPC example client.
// It shows available command-line options, environment variables, and usage examples.
func printUsage() {
	log.Printf("Usage: %s [options]", os.Args[0])
	log.Println()
	log.Println("Options:")
	log.Println("  -server <address>  gRPC server address (default: localhost:8080)")
	log.Println("  -help              Show this help message")
	log.Println()
	log.Println("Environment variables:")
	log.Println("  GRPC_SERVER        gRPC server address (overrides default)")
	log.Println()
	log.Println("Examples:")
	log.Println("  go run main.go                           # Connect to localhost:8080")
	log.Println("  go run main.go -server=localhost:9090    # Connect to localhost:9090")
	log.Println("  GRPC_SERVER=localhost:9090 go run main.go # Connect using environment variable")
}
