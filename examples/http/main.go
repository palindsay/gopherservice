package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// main is the entry point for the HTTP example client.
// It demonstrates how to interact with the gopherservice via its HTTP/REST API.
func main() {
	// Call createPet to add a new pet to the store.
	createPet()

	// Call getPet to retrieve the pet that was just created.
	getPet()
}

// createPet demonstrates how to create a new pet using the REST API.
// It marshals a pet object into JSON and sends a POST request to the /v1/pets endpoint.
// It logs the response from the server or a fatal error if the request fails.
func createPet() {
	log.Println("--- CreatePet ---")
	pet := &v1.Pet{
		Id:      "1",
		Name:    "Fido",
		Species: "dog",
	}
	jsonPet, err := json.Marshal(pet)
	if err != nil {
		log.Fatalf("could not marshal pet: %v", err)
	}

	resp, err := http.Post("http://localhost:8081/v1/pets", "application/json", bytes.NewBuffer(jsonPet))
	if err != nil {
		log.Fatalf("could not create pet: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read response body: %v", err)
	}

	log.Printf("Created pet: %s", body)
}

// getPet demonstrates how to retrieve a pet by its ID using the REST API.
// It sends a GET request to the /v1/pets/{id} endpoint.
// It logs the response from the server or a fatal error if the request fails.
func getPet() {
	log.Println("--- GetPet ---")
	resp, err := http.Get("http://localhost:8081/v1/pets/1")
	if err != nil {
		log.Fatalf("could not get pet: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read response body: %v", err)
	}

	log.Printf("Got pet: %s", body)
}
