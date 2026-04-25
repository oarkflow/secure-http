import { test, expect } from "@playwright/test";

test("login page renders secure workspace entry flow", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Sign in to the encrypted workspace" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
    await expect(page.getByText("Sample Accounts")).toBeVisible();
});

test("user can sign in and reach the authenticated workspace", async ({ page }) => {
    await page.goto("/login");

    await page.getByLabel("Username").fill("alice");
    await page.getByLabel("Password").fill("alice-password");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByRole("heading", { name: "Ops Workspace" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Secure channel is ready" })).toBeVisible();
    await expect(page.getByText("todo-alice")).toBeVisible();
    await expect(page.getByRole("link", { name: "Todos" })).toBeVisible();
});
