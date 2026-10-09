import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { ImageList } from '@/features/sources/image-list'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const page = (items: unknown[]) => ({ items, total: items.length, limit: 25, offset: 0, counts: { all: items.length, unlinked: items.length, label: 0, manual: 0 }, repositories: {} })
const PENDING = { key: 'image:ghcr.io/org/app', name: 'ghcr.io/org/app', reference: 'ghcr.io/org/app:1.4.2', last_scan: null, last_complete: null, analyzed: false, built_from: null }
const SCANNED = { key: 'image:docker.io/org/web', name: 'docker.io/org/web', reference: 'docker.io/org/web:1', analyzed: true, built_from: null,
  last_scan: { run_id: 'r1', created_at: '2026-09-01T00:00:00Z', status: 'completed' }, last_complete: '2026-09-01T00:00:00Z' }
const list = (admin: boolean) => <ImageList admin={admin} repository={null} onClearRepository={() => {}} onOpenFindings={() => {}} onNew={() => {}} />

describe('images page', () => {
  it('adds an image without scanning it and announces it', async () => {
    let items: unknown[] = []
    const calls = mockApi(call => {
      if (call.path.startsWith('/api/images') && call.method === 'GET') return { body: page(items) }
      if (call.path === '/api/images') {
        items = [PENDING]
        return { body: { key: PENDING.key, name: PENDING.name, reference: PENDING.reference, created: true, analyzed: false, built_from: null, run: null } }
      }
    })
    const user = userEvent.setup()
    renderWithQueries(list(false))
    // Empty: it offers adding one as well as scanning one.
    await screen.findByText(tr('images.none'))
    await user.click(screen.getAllByRole('button', { name: tr('images.add.open') })[0])
    const dialog = await screen.findByRole('dialog')
    // Only an administrator links an image to a repository.
    expect(within(dialog).queryByText(tr('images.add.built_from'))).toBeNull()
    expect((within(dialog).getByRole('checkbox', { name: new RegExp(tr('images.add.scan_now')) }) as HTMLInputElement).checked).toBe(false)
    await user.type(within(dialog).getByLabelText(tr('images.add.reference')), ' ghcr.io/org/app:1.4.2 ')
    await user.click(within(dialog).getByRole('button', { name: tr('images.add.submit') }))

    expect(calls.find(call => call.method === 'POST')).toEqual({ method: 'POST', path: '/api/images', action: 'register-image',
      body: { reference: 'ghcr.io/org/app:1.4.2', scan: false } })
    expect(await screen.findByText(tr('images.added', { name: PENDING.name }))).toBeTruthy()
    expect(await screen.findByText(tr('images.not_analyzed'))).toBeTruthy()
    expect(screen.getByRole('button', { name: tr('images.scan_for', { name: PENDING.name }) })).toBeTruthy()
    expect(screen.queryByRole('button', { name: tr('images.findings_for', { name: PENDING.name }) })).toBeNull()
    expect(screen.queryByRole('button', { name: tr('images.remove_for', { name: PENDING.name }) })).toBeNull()
  })

  it('shows why an image could not be added, inside the dialog', async () => {
    mockApi(call => {
      if (call.method === 'GET') return { body: page([]) }
      return { status: 400, body: { error: 'Invalid image reference' } }
    })
    const user = userEvent.setup()
    renderWithQueries(list(false))
    await screen.findByText(tr('images.none'))
    await user.click(screen.getAllByRole('button', { name: tr('images.add.open') })[0])
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(tr('images.add.reference')), 'http://x')
    await user.click(within(dialog).getByRole('button', { name: tr('images.add.submit') }))
    expect((await within(dialog).findByRole('alert')).textContent).toBe('Invalid image reference')
  })

  it('lets an administrator remove an image that was never scanned', async () => {
    let items: unknown[] = [PENDING, SCANNED]
    const calls = mockApi(call => {
      if (call.method === 'GET') return { body: page(items) }
      if (call.path === '/api/images/remove') { items = [SCANNED]; return { body: { key: PENDING.key } } }
    })
    const user = userEvent.setup()
    renderWithQueries(list(true))
    // Asks first; declining sends nothing.
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true)
    await user.click(await screen.findByRole('button', { name: tr('images.remove_for', { name: PENDING.name }) }))
    expect(calls.some(call => call.method === 'POST')).toBe(false)
    await user.click(screen.getByRole('button', { name: tr('images.remove_for', { name: PENDING.name }) }))
    expect(confirm).toHaveBeenCalledTimes(2)
    confirm.mockRestore()
    expect(calls.find(call => call.method === 'POST')).toEqual({ method: 'POST', path: '/api/images/remove', action: 'remove-image', body: { key: PENDING.key } })
    expect(await screen.findByText(tr('images.removed', { name: PENDING.name }))).toBeTruthy()
    // A scanned image keeps its history: no remove button, and its findings are one click away.
    expect(screen.queryByRole('button', { name: tr('images.remove_for', { name: SCANNED.name }) })).toBeNull()
    expect(screen.getByRole('button', { name: tr('images.findings_for', { name: SCANNED.name }) })).toBeTruthy()
  })

  it('says why a removal failed next to that image, and the scan button stays', async () => {
    mockApi(call => call.method === 'GET' ? { body: page([PENDING]) } : { status: 409, body: { error: 'That image has been analyzed.' } })
    const user = userEvent.setup()
    renderWithQueries(list(true))
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    await user.click(await screen.findByRole('button', { name: tr('images.remove_for', { name: PENDING.name }) }))
    confirm.mockRestore()
    expect((await screen.findByRole('alert')).textContent).toBe('That image has been analyzed.')
    expect(screen.getByRole('button', { name: tr('images.scan_for', { name: PENDING.name }) }).hasAttribute('disabled')).toBe(false)
  })
})
