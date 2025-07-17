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

// Package main provides an example HTTP/REST client for the gopherservice.
// It demonstrates how to interact with the gRPC-Gateway HTTP endpoints,
// including user authentication, JWT token management, and pet store operations.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	v1 "github.com/plindsay/gopherservice/api/v1"
)

// Global variable to store the base URL
var baseURL string

// main is the entry point for the HTTP example client.
// It demonstrates how to interact with the gopherservice via its HTTP/REST API.
func main() {
	// Define command-line flags
	var (
		server = flag.String("server", getEnv("HTTP_SERVER", "localhost:8081"), "HTTP server address")
		help   = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	// Set the base URL
	baseURL = fmt.Sprintf("http://%s", *server)
	log.Printf("Connecting to HTTP server at %s", baseURL)

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

// registerAndLogin registers a new user and logs in to obtain access and refresh tokens.
// It sends HTTP requests to the registration and login endpoints.
// Returns the access token and refresh token as strings.
func registerAndLogin() (string, string) {
	log.Println("--- Registering User ---")
	registerReq := map[string]interface{}{
		"email":    "httpuser@example.com",
		"password": "password",
		"fullName": "HTTP User",
		"roles":    []string{"user"},
	}
	jsonRegisterReq, err := json.Marshal(registerReq)
	if err != nil {
		log.Fatalf("could not marshal register request: %v", err)
	}

	resp, err := http.Post(baseURL+"/v1/auth/register", "application/json", bytes.NewBuffer(jsonRegisterReq))
	if err != nil {
		log.Printf("could not register user (might already exist): %v", err)
	}
	resp.Body.Close()

	log.Println("--- Logging In ---")
	loginReq := map[string]interface{}{
		"credentials": map[string]interface{}{
			"email":    "httpuser@example.com",
			"password": "password",
		},
	}
	jsonLoginReq, err := json.Marshal(loginReq)
	if err != nil {
		log.Fatalf("could not marshal login request: %v", err)
	}

	resp, err = http.Post(baseURL+"/v1/auth/login", "application/json", bytes.NewBuffer(jsonLoginReq))
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
	petData := map[string]interface{}{
		"pet": map[string]interface{}{
			"id":      "1",
			"name":    "Fido",
			"species": "dog",
		},
	}
	jsonPet, err := json.Marshal(petData)
	if err != nil {
		log.Fatalf("could not marshal pet: %v", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/v1/pets", bytes.NewBuffer(jsonPet))
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
	req, err := http.NewRequest("GET", baseURL+"/v1/pets/1", nil)
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

// refreshToken uses a refresh token to obtain a new access token via HTTP.
// It sends an HTTP POST request to the refresh endpoint with the refresh token.
// Returns the new access token as a string.
func refreshToken(refreshToken string) string {
	log.Println("--- Refreshing Token ---")
	refreshReq := map[string]interface{}{
		"refreshToken": refreshToken,
	}
	jsonRefreshReq, err := json.Marshal(refreshReq)
	if err != nil {
		log.Fatalf("could not marshal refresh request: %v", err)
	}

	resp, err := http.Post(baseURL+"/v1/auth/refresh", "application/json", bytes.NewBuffer(jsonRefreshReq))
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

	if refreshRes.Token == nil {
		log.Printf("refresh response: %s", body)
		log.Fatalf("token refresh not implemented on server")
	}

	log.Println("Token refreshed successfully.")
	return refreshRes.Token.AccessToken
}

// getEnv returns the value of an environment variable or a default value if not set.
// It provides a simple way to configure the client through environment variables.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// printUsage prints usage information for the HTTP example client.
// It shows available command-line options, environment variables, and usage examples.
func printUsage() {
	log.Printf("Usage: %s [options]", os.Args[0])
	log.Println()
	log.Println("Options:")
	log.Println("  -server <address>  HTTP server address (default: localhost:8081)")
	log.Println("  -help              Show this help message")
	log.Println()
	log.Println("Environment variables:")
	log.Println("  HTTP_SERVER        HTTP server address (overrides default)")
	log.Println()
	log.Println("Examples:")
	log.Println("  go run main.go                           # Connect to localhost:8081")
	log.Println("  go run main.go -server=localhost:9091    # Connect to localhost:9091")
	log.Println("  HTTP_SERVER=localhost:9091 go run main.go # Connect using environment variable")
}
