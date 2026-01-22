package middleware

import "github.com/gofiber/fiber/v2"

func respondNotFound(c *fiber.Ctx) error {
	if c == nil {
		return nil
	}
	c.Response().Reset()
	return c.SendStatus(fiber.StatusOK)
}
