package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/oarkflow/securehttp/pkg/config"
	"github.com/oarkflow/securehttp/pkg/http/middleware"
	"github.com/oarkflow/securehttp/pkg/security"
)

type UserRequest struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type UserResponse struct {
	Status  int    `json:"status"`
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func main() {
	configPath := flag.String("config", defaultConfigPath(), "Path to server configuration JSON")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("load server config: %v", err)
	}

	auditLogger, cleanup, err := cfg.BuildAuditLogger()
	if err != nil {
		log.Fatalf("initialize audit logger: %v", err)
	}
	defer cleanup()

	capStore, err := cfg.BuildCapabilityStore()
	if err != nil {
		log.Fatalf("build capability store: %v", err)
	}

	gateCfg, err := cfg.GatekeeperConfig(capStore, auditLogger)
	if err != nil {
		log.Fatalf("compose gatekeeper config: %v", err)
	}
	gatekeeper, err := security.NewGatekeeper(gateCfg)
	if err != nil {
		log.Fatalf("initialize gatekeeper: %v", err)
	}

	deviceRegistry, err := cfg.BuildDeviceRegistry()
	if err != nil {
		log.Fatalf("build device registry: %v", err)
	}

	userAuth, err := cfg.BuildUserAuthenticator()
	if err != nil {
		log.Fatalf("build user authenticator: %v", err)
	}

	policy := &security.SecurityPolicy{
		RequireDevice:     cfg.Auth.RequireDevice,
		RequireUser:       cfg.Auth.RequireUser,
		DeviceRegistry:    deviceRegistry,
		UserAuthenticator: userAuth,
		Logger:            auditLogger,
	}

	cryptoMiddleware, err := middleware.NewCryptoMiddleware(policy)
	if err != nil {
		log.Fatalf("initialize crypto middleware: %v", err)
	}

	app := fiber.New(fiber.Config{
		BodyLimit: 10 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			c.Response().Reset()
			return c.SendStatus(fiber.StatusNotFound)
		},
	})

	gateMiddleware := middleware.NewGateMiddleware(gatekeeper)
	app.Use(gateMiddleware.Handle())

	app.Use(recover.New())
	app.Use(logger.New())

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
			Status:  200,
			Success: true,
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
			Status:  200,
			Success: true,
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
			Status:  200,
			Success: true,
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

	log.Printf("🚀 Secure server starting on %s (config: %s)", cfg.ListenAddr, *configPath)
	log.Println("📡 Handshake endpoint: POST /handshake")
	log.Println("🔒 Encrypted endpoints: POST /api/*")
	log.Fatal(app.Listen(cfg.ListenAddr))
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

func defaultConfigPath() string {
	if val := os.Getenv("SECURE_HTTP_CONFIG"); val != "" {
		return val
	}
	return "config/server.json"
}
