package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/oarkflow/securehttp/pkg/http/client"
)

type UserRequest struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type UserResponse struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

func main() {
	cfg := client.Config{
		BaseURL:      "http://localhost:8443",
		DeviceID:     "device-001",
		DeviceSecret: []byte("device-001-secret"),
		UserToken:    "user-token-123",
	}

	secureClient, err := client.NewSecureClient(cfg)
	if err != nil {
		log.Fatal("Failed to create client:", err)
	}

	// Perform handshake to establish secure session
	log.Println("🤝 Performing handshake...")
	if err := secureClient.Handshake(); err != nil {
		log.Fatal("Handshake failed:", err)
	}
	log.Println("✅ Handshake successful, secure session established")

	// Example 1: Echo endpoint
	log.Println("\n📤 Sending echo request...")
	echoReq := UserRequest{
		Name:    "John Doe",
		Message: "Hello, secure server!",
	}

	var echoResp UserResponse
	if err := secureClient.PostJSON("/api/echo", echoReq, &echoResp); err != nil {
		log.Printf("Echo request failed: %v", err)
	} else {
		log.Printf("✅ Echo response: %s", echoResp.Message)
		prettyPrint(echoResp.Data)
	}

	time.Sleep(time.Second)

	// Example 2: User info endpoint
	log.Println("\n📤 Fetching user info...")
	userReq := UserRequest{
		Name:    "Jane Smith",
		Message: "Get user information",
	}

	var userResp UserResponse
	if err := secureClient.PostJSON("/api/user/info", userReq, &userResp); err != nil {
		log.Printf("User info request failed: %v", err)
	} else {
		log.Printf("✅ User info response: %s", userResp.Message)
		prettyPrint(userResp.Data)
	}

	time.Sleep(time.Second)

	// Example 3: Create resource endpoint
	log.Println("\n📤 Creating resource...")
	resourceReq := UserRequest{
		Name:    "My Important Resource",
		Message: "admin@example.com",
	}

	var resourceResp UserResponse
	if err := secureClient.PostJSON("/api/resource/create", resourceReq, &resourceResp); err != nil {
		log.Printf("Resource creation failed: %v", err)
	} else {
		log.Printf("✅ Resource created: %s", resourceResp.Message)
		prettyPrint(resourceResp.Data)
	}

	// Example 4: Multiple rapid requests to test session reuse
	log.Println("\n📤 Sending multiple rapid requests...")
	for i := 0; i < 5; i++ {
		req := UserRequest{
			Name:    "Test User",
			Message: "Rapid fire message " + string(rune('A'+i)),
		}

		var resp UserResponse
		if err := secureClient.PostJSON("/api/echo", req, &resp); err != nil {
			log.Printf("Request %d failed: %v", i+1, err)
		} else {
			log.Printf("✅ Request %d successful: %s", i+1, resp.Status)
		}
		time.Sleep(200 * time.Millisecond)
	}

	log.Println("\n🎉 All requests completed successfully!")
}

func prettyPrint(data interface{}) {
	if data == nil {
		return
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("Data: %+v", data)
		return
	}
	log.Printf("Data:\n%s", string(jsonData))
}
