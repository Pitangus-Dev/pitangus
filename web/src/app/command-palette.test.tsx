import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { CommandPalette } from '@/app/command-palette'
import { dialogOpen, useShortcuts } from '@/shared/lib/shortcuts'
import { mockApi, type Call } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'

const run = { id: 'run-1234567890', type: 'repository_scan', status: 'completed', created_at: '2026-10-01T10:00:00Z', source: { name: 'acme/payments', provider: 'github' }, summary: {} }
const asset = { key: 'github:acme/payments', name: 'acme/payments', provider: 'github', scans: 2, pr_reviews: 0, last_activity: '2026-10-01', removed_at: null, latest_scan: null, open: { total: 3, critical: 0, high: 1, medium: 2, low: 0 } }
const domain = { id: 'dom-1', host: 'payments.acme.test', url: 'https://payments.acme.test', kind: 'web' }

const answer = (call: Call) => {
  if (call.path.startsWith('/api/runs/page')) return { body: { items: [run], total: 1, limit: 5, offset: 0 } }
  if (call.path.startsWith('/api/assets')) return { body: { items: [asset], total: 1, limit: 50, offset: 0 } }
  if (call.path.startsWith('/api/domains')) return { body: { items: [domain], total: 1, limit: 100, dast: true } }
  return undefined
}

type Handlers = Record<string, ReturnType<typeof vi.fn<(value?: string) => void>>>

function Harness({ admin = true, handlers }: { admin?: boolean; handlers: Handlers }) {
  const [open, setOpen] = useState(false)
  useShortcuts({
    palette: () => setOpen(current => current ? false : !dialogOpen()),
    help: handlers.help, create: handlers.create,
    go: letter => { handlers.go(letter); return letter === 'f' },
  })
  return <>
    <button type="button">Before</button>
    <label>Notes <input /></label>
    <CommandPalette open={open} onOpenChange={setOpen} admin={admin} onView={handlers.view} onImport={handlers.importResults}
      onAddDomain={handlers.addDomain} onHelp={handlers.help} onOpenRun={handlers.openRun} onOpenDomain={handlers.openDomain} onOpenAsset={handlers.openAsset} />
  </>
}

const setup = (admin = true) => {
  const handlers = Object.fromEntries(['help', 'create', 'go', 'view', 'importResults', 'addDomain', 'openRun', 'openDomain', 'openAsset'].map(name => [name, vi.fn<(value?: string) => void>()])) as Handlers
  const user = userEvent.setup()
  const calls = mockApi(answer)
  renderWithQueries(<Harness admin={admin} handlers={handlers} />)
  return { user, handlers, calls }
}

const optionNames = () => within(screen.getByRole('listbox')).getAllByRole('option').map(option => option.textContent ?? '')

describe('command palette', () => {
  beforeEach(() => { window.location.hash = '' })
  afterEach(() => vi.unstubAllGlobals())

  it('opens with Ctrl+K, focuses the search and closes with Escape, returning the focus', async () => {
    const { user } = setup()
    const before = screen.getByRole('button', { name: 'Before' })
    before.focus()
    await user.keyboard('{Control>}k{/Control}')
    const input = await screen.findByRole('combobox', { name: /search pages/i })
    await waitFor(() => expect(document.activeElement).toBe(input))
    expect(screen.getByRole('dialog', { name: 'Search and commands' })).toBeTruthy()
    expect(optionNames()[0]).toContain('New scan')
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await waitFor(() => expect(document.activeElement).toBe(before))
  })

  it('filters actions and pages by what is typed, ignoring accents', async () => {
    const { user } = setup()
    await user.keyboard('{Control>}k{/Control}')
    await user.type(await screen.findByRole('combobox'), 'integrations')
    await waitFor(() => expect(optionNames()).toEqual([expect.stringContaining('Integrations')]))
    await user.clear(screen.getByRole('combobox'))
    await user.type(screen.getByRole('combobox'), 'ímport')
    await waitFor(() => expect(optionNames()[0]).toContain('Import SARIF results'))
  })

  it('moves with the arrows (aria-activedescendant) and opens with Enter', async () => {
    const { user, handlers } = setup()
    await user.keyboard('{Control>}k{/Control}')
    const input = await screen.findByRole('combobox')
    const first = screen.getAllByRole('option')[0]
    expect(input.getAttribute('aria-activedescendant')).toBe(first.id)
    expect(first.getAttribute('aria-selected')).toBe('true')
    await user.keyboard('{ArrowDown}')
    const second = screen.getAllByRole('option')[1]
    expect(input.getAttribute('aria-activedescendant')).toBe(second.id)
    await user.keyboard('{ArrowUp}{ArrowUp}')
    const options = screen.getAllByRole('option')
    expect(input.getAttribute('aria-activedescendant')).toBe(options[options.length - 1].id)
    await user.keyboard('{ArrowDown}{Enter}')
    expect(handlers.view).toHaveBeenCalledWith('new')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('searches scans, repositories and domains on the server and opens them', async () => {
    const { user, handlers, calls } = setup()
    await user.keyboard('{Control>}k{/Control}')
    await user.type(await screen.findByRole('combobox'), 'payments')
    const domainOption = await screen.findByRole('option', { name: /payments\.acme\.test/ })
    await waitFor(() => expect(screen.getAllByRole('option', { name: /acme\/payments/ })).toHaveLength(2))
    expect(calls.some(call => call.path === '/api/runs/page?q=payments&limit=5')).toBe(true)
    expect(calls.some(call => call.path.startsWith('/api/assets?q=payments'))).toBe(true)
    await user.click(domainOption)
    expect(handlers.openDomain).toHaveBeenCalledWith('dom-1')
  })

  it('shows administrator-only pages and actions to administrators only', async () => {
    const member = setup(false)
    await member.user.keyboard('{Control>}k{/Control}')
    await screen.findByRole('combobox')
    expect(optionNames().some(name => name.includes('Users'))).toBe(false)
    expect(optionNames().some(name => name.includes('Add a domain'))).toBe(false)
    await member.user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('lists the users page and the add-domain action for administrators', async () => {
    const { user, handlers } = setup(true)
    await user.keyboard('{Control>}k{/Control}')
    await user.type(await screen.findByRole('combobox'), 'add a domain')
    await user.keyboard('{Enter}')
    expect(handlers.addDomain).toHaveBeenCalled()
    await user.keyboard('{Control>}k{/Control}')
    await user.type(await screen.findByRole('combobox'), 'users')
    await waitFor(() => expect(optionNames()).toEqual([expect.stringMatching(/Users.*G.*U/)]))
  })
})

describe('keyboard shortcuts', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('runs N, ? and G then a letter outside text fields', async () => {
    const { user, handlers } = setup()
    await user.keyboard('n')
    expect(handlers.create).toHaveBeenCalledTimes(1)
    await user.keyboard('?')
    expect(handlers.help).toHaveBeenCalledTimes(1)
    await user.keyboard('gf')
    expect(handlers.go).toHaveBeenCalledWith('f')
  })

  it('ignores single-key shortcuts while typing in a field', async () => {
    const { user, handlers } = setup()
    await user.click(screen.getByRole('textbox', { name: 'Notes' }))
    await user.keyboard('n?gf')
    expect(handlers.create).not.toHaveBeenCalled()
    expect(handlers.help).not.toHaveBeenCalled()
    expect(handlers.go).not.toHaveBeenCalled()
    expect((screen.getByRole('textbox', { name: 'Notes' }) as HTMLInputElement).value).toBe('n?gf')
  })

  it('ignores them while a dialog is open, the palette included', async () => {
    const { user, handlers } = setup()
    await user.keyboard('{Control>}k{/Control}')
    await screen.findByRole('dialog')
    screen.getByRole('combobox').blur()
    await user.keyboard('n')
    expect(handlers.create).not.toHaveBeenCalled()
  })
})
