import { test, expect } from '@playwright/test'

test.describe('Landing page', () => {
  test('has title "Freewallet"', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveTitle('Freewallet')
  })

  test('shows app name and nav buttons', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: 'Freewallet', level: 1 })
    ).toBeVisible()
    await expect(page.getByRole('link', { name: 'Log in' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Sign Up' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Guest Mode' })).toBeVisible()
  })

  test('Log in button navigates to login screen', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Log in' }).click()
    await expect(page).toHaveURL(/#\/login/)
    await expect(
      page.getByRole('heading', { name: 'Log in', level: 1 })
    ).toBeVisible()
  })

  test('Sign Up button navigates to sign up screen', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Sign Up' }).click()
    await expect(page).toHaveURL(/#\/signup/)
    await expect(
      page.getByRole('heading', { name: 'Sign up', level: 1 })
    ).toBeVisible()
  })

  test('Guest Mode button navigates to guest login screen', async ({
    page
  }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Guest Mode' }).click()
    await expect(page).toHaveURL(/#\/guest-login/)
    await expect(
      page.getByRole('heading', { name: 'Guest Mode Login', level: 1 })
    ).toBeVisible()
  })
})
