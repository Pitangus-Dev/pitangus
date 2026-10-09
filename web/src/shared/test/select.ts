import { expect } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import type { UserEvent } from '@testing-library/user-event'

// Drives a shared/ui Select like a person: open the list, then click the option by its visible label.
export async function choose(user: UserEvent, trigger: HTMLElement, label: string) {
  await user.click(trigger)
  await user.click(await screen.findByRole('option', { name: label }))
  await waitFor(() => expect(trigger.getAttribute('aria-expanded')).toBe('false'))
}

// The labels a Select offers (it opens the list and closes it again).
export async function optionsOf(user: UserEvent, trigger: HTMLElement) {
  await user.click(trigger)
  const listbox = await screen.findByRole('listbox')
  const labels = [...listbox.querySelectorAll('[role=option]')].map(option => option.textContent)
  await user.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('listbox')).toBeNull())
  return labels
}
