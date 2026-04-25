import { test, expect } from "@playwright/test";

test("lab page loads secure http controls", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=secureFetch WebAssembly Demo")).toBeVisible();
    await expect(page.locator("#login-btn")).toBeVisible();
    await expect(page.locator("#echo-btn")).toBeDisabled();
});

test("lab login configures the secure client and unlocks protected actions", async ({ page }) => {
    await page.goto("/");

    await page.locator("#user-id").fill("user-123");
    await page.locator("#user-token").fill("user-token-123");
    await page.locator("#login-btn").click();

    await expect(page.locator("#status-indicator")).toContainText("Logged in as user-123");
    await expect(page.locator("#echo-btn")).toBeEnabled();
    await expect(page.locator("#session-btn")).toBeEnabled();
    await expect(page.locator("#console")).toContainText("Application login successful");
});
