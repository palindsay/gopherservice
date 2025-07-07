package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// main is the entry point for the HTTP example client.
// It demonstrates how to interact with the gopherservice via its HTTP/REST API.
func main() {
	// Register and login to get a token
	accessToken, initialRefreshToken := registerAndLogin()

	// Call createPet to add a new pet to the store.
	createPet(accessToken)

	// Call getPet to retrieve the pet that was just created.
	getPet(accessToken)

	// Refresh the token
	newAccessToken := refreshToken(initialRefreshToken)

	// Call getPet again with the new token
	getPet(newAccessToken)
}

func registerAndLogin() (string, string) {
	log.Println("--- Registering User ---")
	registerReq := v1.RegisterUserRequest{
		Email:    "httpuser@example.com",
		Password: "password",
		FullName: "HTTP User",
		Roles:    []string{"user"},
	}
	jsonRegisterReq, err := json.Marshal(registerReq)
	if err != nil {
		log.Fatalf("could not marshal register request: %v", err)
	}

	resp, err := http.Post("http://localhost:8081/v1/auth/register", "application/json", bytes.NewBuffer(jsonRegisterReq))
	if err != nil {
		log.Printf("could not register user (might already exist): %v", err)
	}
	resp.Body.Close()

	log.Println("--- Logging In ---")
	loginReq := v1.LoginRequest{
		Credentials: &v1.UserCredentials{
			Email:    "httpuser@example.com",
			Password: "password",
		},
	}
	jsonLoginReq, err := json.Marshal(loginReq)
	if err != nil {
		log.Fatalf("could not marshal login request: %v", err)
	}

	resp, err = http.Post("http://localhost:8081/v1/auth/login", "application/json", bytes.NewBuffer(jsonLoginReq))
	if err != nil {
		log.Fatalf("could not login: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read login response body: %v", err)
	}

	var loginRes v1.LoginResponse
	err = json.Unmarshal(body, &loginRes)
	if err != nil {
		log.Fatalf("could not unmarshal login response: %v", err)
	}

	log.Println("Logged in successfully, got token.")
	return loginRes.Token.AccessToken, loginRes.Token.RefreshToken
}

// createPet demonstrates how to create a new pet using the REST API.
// It marshals a pet object into JSON and sends a POST request to the /v1/pets endpoint.
// It logs the response from the server or a fatal error if the request fails.
func createPet(accessToken string) {
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

	req, err := http.NewRequest("POST", "http://localhost:8081/v1/pets", bytes.NewBuffer(jsonPet))
	if err != nil {
		log.Fatalf("could not create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("could not create pet: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read response body: %v", err)
	}

	log.Printf("Created pet: %s", body)
}

// getPet demonstrates how to retrieve a pet by its ID using the REST API.
// It sends a GET request to the /v1/pets/{id} endpoint.
// It logs the response from the server or a fatal error if the request fails.
func getPet(accessToken string) {
	log.Println("--- GetPet ---")
	req, err := http.NewRequest("GET", "http://localhost:8081/v1/pets/1", nil)
	if err != nil {
		log.Fatalf("could not create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("could not get pet: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read response body: %v", err)
	}

	log.Printf("Got pet: %s", body)
}

func refreshToken(refreshToken string) string {
	log.Println("--- Refreshing Token ---")
	refreshReq := v1.RefreshTokenRequest{RefreshToken: refreshToken}
	jsonRefreshReq, err := json.Marshal(refreshReq)
	if err != nil {
		log.Fatalf("could not marshal refresh request: %v", err)
	}

	resp, err := http.Post("http://localhost:8081/v1/auth/refresh", "application/json", bytes.NewBuffer(jsonRefreshReq))
	if err != nil {
		log.Fatalf("could not refresh token: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("could not read refresh response body: %v", err)
	}

	var refreshRes v1.RefreshTokenResponse
	err = json.Unmarshal(body, &refreshRes)
	if err != nil {
		log.Fatalf("could not unmarshal refresh response: %v", err)
	}

	log.Println("Token refreshed successfully.")
	return refreshRes.Token.AccessToken
}
