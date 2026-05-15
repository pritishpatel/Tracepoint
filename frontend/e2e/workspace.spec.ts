import { expect, test } from "@playwright/test";

test("workspace renders the operational dashboard", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "SecOps command center" })).toBeVisible();
  await expect(page.getByText("KEV urgency queue")).toBeVisible();
});

test("findings route supports table search", async ({ page }) => {
  await page.goto("/findings");
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
  await page.getByPlaceholder("Search title, asset, source, category, reporter").fill("invoice");
  await expect(page.getByText("IDOR in invoice retrieval")).toBeVisible();
});

test("import route exposes validation workflow", async ({ page }) => {
  await page.goto("/import");
  await expect(page.getByRole("heading", { name: "Intake and bulk import" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run import" })).toBeVisible();
});
