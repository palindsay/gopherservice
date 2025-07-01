package main

import (
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

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

	// Create a new PetStore client using the established gRPC connection.
	client := v1.NewPetStoreServiceClient(conn)

	// Call the createPet function to add a new pet to the store.
	createPet(client)

	// Call the getPet function to retrieve the pet that was just created.
	getPet(client)
}

// createPet demonstrates how to create a new pet using the PetStoreServiceClient.
// It takes a PetStoreServiceClient as input and attempts to create a pet with ID "1", Name "Fido", and Species "dog".
// It logs the created pet or a fatal error if the creation fails.
func createPet(client v1.PetStoreServiceClient) {
	log.Println("--- CreatePet ---")
	pet := &v1.Pet{
		Id:      "1",
		Name:    "Fido",
		Species: "dog",
	}
	req := &v1.CreatePetRequest{Pet: pet}
	res, err := client.CreatePet(context.Background(), req)
	if err != nil {
		log.Fatalf("could not create pet: %v", err)
	}
	log.Printf("Created pet: %v", res.GetPet())
}

// getPet demonstrates how to retrieve a pet by its ID using the PetStoreServiceClient.
// It takes a PetStoreServiceClient as input and attempts to retrieve the pet with ID "1".
// It logs the retrieved pet or a fatal error if the retrieval fails.
func getPet(client v1.PetStoreServiceClient) {
	log.Println("--- GetPet ---")
	req := &v1.GetPetRequest{Id: "1"}
	res, err := client.GetPet(context.Background(), req)
	if err != nil {
		log.Fatalf("could not get pet: %v", err)
	}
	log.Printf("Got pet: %v", res.GetPet())
}
