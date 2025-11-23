package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/oarkflow/securehttp/pkg/http/middleware"
	"github.com/oarkflow/securehttp/pkg/security"
)

type UserRequest struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type UserResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func main() {
	app := fiber.New(fiber.Config{
		BodyLimit: 10 * 1024 * 1024,
	})

	app.Use(recover.New())
	app.Use(logger.New())

	deviceRegistry := security.NewInMemoryDeviceRegistry()
	deviceRegistry.Register("device-001", []byte("device-001-secret"))
	deviceRegistry.Register("device-002", []byte("device-002-secret"))

	userAuth := security.NewStaticUserAuthenticator()
	userAuth.Register("user-token-123", &security.UserContext{
		ID:    "user-123",
		Roles: []string{"admin", "device-owner"},
		Metadata: map[string]string{
			"email": "owner@example.com",
		},
	})
	userAuth.Register("user-token-456", &security.UserContext{
		ID:    "user-456",
		Roles: []string{"operator"},
	})

	policy := &security.SecurityPolicy{
		RequireDevice:     true,
		RequireUser:       true,
		DeviceRegistry:    deviceRegistry,
		UserAuthenticator: userAuth,
	}

	cryptoMiddleware, err := middleware.NewCryptoMiddleware(policy)
	if err != nil {
		log.Fatal("Failed to initialize crypto middleware:", err)
	}

	app.Post("/handshake", cryptoMiddleware.Handshake())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":   "healthy",
			"sessions": cryptoMiddleware.GetSessionManager().SessionCount(),
		})
	})

	api := app.Group("/api")
	api.Use(cryptoMiddleware.Decrypt())
	api.Use(cryptoMiddleware.Encrypt())

	api.Post("/echo", func(c *fiber.Ctx) error {
		decryptedBody, ok := c.Locals("decrypted_body").([]byte)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to get decrypted body",
			})
		}

		var req UserRequest
		if err := json.Unmarshal(decryptedBody, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid JSON in decrypted body",
			})
		}

		response := UserResponse{
			Status:  "success",
			Message: "Echo response",
			Data: fiber.Map{
				"received_name":    req.Name,
				"received_message": req.Message,
				"processed_at":     time.Now(),
				"security":         securityEnvelope(c),
			},
		}

		return c.JSON(response)
	})

	api.Post("/user/info", func(c *fiber.Ctx) error {
		decryptedBody := c.Locals("decrypted_body").([]byte)

		var req UserRequest
		if err := json.Unmarshal(decryptedBody, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request",
			})
		}

		response := UserResponse{
			Status:  "success",
			Message: "User info retrieved",
			Data: fiber.Map{
				"user":     req.Name,
				"bio":      "This is sensitive user data",
				"email":    "user@example.com",
				"security": securityEnvelope(c),
			},
		}

		return c.JSON(response)
	})

	api.Post("/resource/create", func(c *fiber.Ctx) error {
		decryptedBody := c.Locals("decrypted_body").([]byte)

		var req UserRequest
		if err := json.Unmarshal(decryptedBody, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request",
			})
		}

		response := UserResponse{
			Status:  "success",
			Message: "Resource created successfully",
			Data: fiber.Map{
				"resource_id": "res_123456",
				"name":        req.Name,
				"created_by":  req.Message,
				"security":    securityEnvelope(c),
			},
		}

		return c.JSON(response)
	})

	log.Println("🚀 Secure server starting on :8443")
	log.Println("📡 Handshake endpoint: POST /handshake")
	log.Println("🔒 Encrypted endpoints: POST /api/*")
	log.Fatal(app.Listen(":8443"))
}

func securityEnvelope(c *fiber.Ctx) fiber.Map {
	payload := fiber.Map{}
	if deviceID, ok := c.Locals("device_id").(string); ok && deviceID != "" {
		payload["device_id"] = deviceID
	}
	if userCtx, ok := c.Locals("user_context").(*security.UserContext); ok && userCtx != nil {
		payload["user_id"] = userCtx.ID
		if len(userCtx.Roles) > 0 {
			payload["roles"] = userCtx.Roles
		}
	}
	return payload
}
