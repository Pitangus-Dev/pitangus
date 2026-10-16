import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'

const REPOSITORIES: ComboOption[] = [{ id: 'github#1', label: 'org/api' }, { id: 'github#2', label: 'org/web', hint: 'Not analyzed yet' }]
const search = (query: string) => Promise.resolve({ options: REPOSITORIES.filter(option => option.label.includes(query)), total: 2 })

function picker(onSelect = vi.fn(), searchWith = search) {
  // Inside a row that clips what overflows it, as the Images list does.
  render(<ul><li data-testid="row" className="overflow-hidden"><Combobox label="Repository" placeholder="Pick a repository" value={null} delay={0}
    search={searchWith} onSelect={onSelect} emptyText={query => query ? `Nothing matches ${query}` : 'No repositories yet'} /></li></ul>)
  return { onSelect, user: userEvent.setup() }
}

describe('combobox', () => {
  it('floats its list over the page, so a row that clips its content doesn\'t hide it', async () => {
    const { user } = picker()
    await user.click(screen.getByRole('button', { name: 'Repository: Pick a repository' }))
    const listbox = await screen.findByRole('listbox', { name: 'Repository' })
    expect(screen.getByTestId('row').contains(listbox)).toBe(false)
    expect(await screen.findByRole('option', { name: /org\/web/ })).toBeTruthy()
  })

  it('is chosen from the keyboard, and Escape gives the focus back to its button', async () => {
    const { onSelect, user } = picker()
    await user.click(screen.getByRole('button', { name: 'Repository: Pick a repository' }))
    await screen.findByRole('option', { name: /org\/web/ })
    await user.keyboard('{ArrowDown}{Enter}')
    expect(onSelect).toHaveBeenCalledWith(REPOSITORIES[1])
    await user.click(screen.getByRole('button', { name: 'Repository: Pick a repository' }))
    await screen.findByRole('listbox')
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('listbox')).toBeNull())
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Repository: Pick a repository' })))
  })

  it('says why there is nothing to pick: nothing at all, or nothing that matches', async () => {
    const { user } = picker(vi.fn(), () => Promise.resolve({ options: [], total: 0 }))
    await user.click(screen.getByRole('button', { name: 'Repository: Pick a repository' }))
    expect(await screen.findByText('No repositories yet')).toBeTruthy()
    await user.keyboard('zzz')
    expect(await screen.findByText('Nothing matches zzz')).toBeTruthy()
  })
})
