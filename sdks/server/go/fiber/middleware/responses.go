package middleware

import "github.com/gofiber/fiber/v2"

func respondNotFound(c *fiber.Ctx) error {
	if c == nil {
		return nil
	}
	return c.SendStatus(fiber.StatusNotFound)
}

func respondOpaqueAuthFailure(c *fiber.Ctx) error {
	return respondNotFound(c)
}
