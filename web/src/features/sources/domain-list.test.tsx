import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { DomainList } from '@/features/sources/domain-list'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const page = (items: unknown[]) => ({ items, total: items.length, limit: 20 })
const ID = 'a'.repeat(24)
const PENDING = { id: ID, host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: '', key: 'domain:app.example.com', verified: false, expired: false,
  registered_at: '2026-10-01T00:00:00Z', registered_by: 'jefa', verified_at: null, verified_until: null, checked_at: null,
  txt_name: '_pitangus.app.example.com', txt_value: 'pitangus-verify=abc123', runs: 0, open: 0 }
const VERIFIED = { ...PENDING, id: 'b'.repeat(24), host: 'api.example.com', key: 'domain:api.example.com', kind: 'api', verified: true,
  verified_at: '2026-10-02T00:00:00Z', verified_until: '2026-12-31T00:00:00Z', checked_at: '2026-10-08T00:00:00Z', runs: 2, open: 5 }

describe('domains page', () => {
  it('adds a domain and goes straight to its TXT record', async () => {
    let items: unknown[] = []
    const calls = mockApi(call => {
      if (call.method === 'GET') return { body: page(items) }
      if (call.path === '/api/domains') { items = [PENDING]; return { body: PENDING } }
    })
    const user = userEvent.setup()
    renderWithQueries(<DomainList admin onOpenFindings={() => {}} />)
    await screen.findByText(new RegExp(tr('domains.list.empty')))
    await user.click(screen.getByRole('button', { name: tr('domains.list.add') }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(tr('domains.add.domain')), 'app.example.com')
    await user.click(within(dialog).getByRole('button', { name: tr('domains.add.title') }))
    expect(calls.find(call => call.method === 'POST' && call.path === '/api/domains')).toEqual({ method: 'POST', path: '/api/domains', action: 'register-domain',
      body: { url: 'https://app.example.com', kind: 'web', context: '' } })
    // The TXT record to add, with its copy buttons, opens on its own; the list shows the domain as not verified.
    const verify = await screen.findByRole('dialog', { name: tr('domains.verify.title', { host: 'app.example.com' }) })
    expect(within(verify).getByText(PENDING.txt_value)).toBeTruthy()
    expect(within(verify).getByRole('button', { name: tr('domains.verify.copy_value') })).toBeTruthy()
    await user.click(within(verify).getByRole('button', { name: tr('domains.verify.skip') }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(await screen.findByText(tr('domains.list.pending'))).toBeTruthy()
    expect(screen.getByText(tr('domains.list.added', { host: 'app.example.com' }))).toBeTruthy()
  })

  it('verifies from the list and shows what the server said when the record is missing', async () => {
    let attempts = 0
    mockApi(call => {
      if (call.method === 'GET') return { body: page([PENDING]) }
      if (call.path === '/api/domains/verify') {
        attempts += 1
        return attempts === 1 ? { status: 400, body: { error: 'The verification TXT record was not found' } } : { body: { ...PENDING, verified: true, verified_until: '2027-01-07T00:00:00Z' } }
      }
    })
    const user = userEvent.setup()
    renderWithQueries(<DomainList admin onOpenFindings={() => {}} />)
    await user.click(await screen.findByRole('button', { name: tr('domains.list.verify_for', { host: 'app.example.com' }) }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: tr('domains.verify.submit') }))
    expect((await within(dialog).findByRole('alert')).textContent).toBe('The verification TXT record was not found')
    await user.click(within(dialog).getByRole('button', { name: tr('domains.verify.submit') }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(screen.getByRole('status').textContent).toContain('app.example.com')
  })

  it('members see the domains without the record or the actions', async () => {
    mockApi(() => ({ body: page([{ ...VERIFIED, txt_name: undefined, txt_value: undefined }]) }))
    const opened: string[] = []
    renderWithQueries(<DomainList admin={false} onOpenFindings={key => opened.push(key)} />)
    expect(await screen.findByText('api.example.com')).toBeTruthy()
    expect(screen.getByText(tr('domains.list.read_only'))).toBeTruthy()
    expect(screen.queryByRole('button', { name: tr('domains.list.add') })).toBeNull()
    expect(screen.queryByRole('button', { name: tr('domains.list.remove_for', { host: 'api.example.com' }) })).toBeNull()
    expect(screen.queryByText(PENDING.txt_value)).toBeNull()
    await userEvent.setup().click(screen.getByRole('button', { name: tr('domains.list.findings_for', { host: 'api.example.com' }) }))
    expect(opened).toEqual(['domain:api.example.com'])
  })

  it('removing a domain with imports says what goes with it, and asks first', async () => {
    let items: unknown[] = [VERIFIED]
    const calls = mockApi(call => {
      if (call.method === 'GET') return { body: page(items) }
      if (call.path === '/api/domains/remove') { items = []; return { body: { id: VERIFIED.id, host: VERIFIED.host, runs_deleted: 2 } } }
    })
    const user = userEvent.setup()
    renderWithQueries(<DomainList admin onOpenFindings={() => {}} />)
    await user.click(await screen.findByRole('button', { name: tr('domains.list.remove_for', { host: 'api.example.com' }) }))
    let question = await screen.findByRole('alertdialog', { name: tr('domains.list.remove_title', { host: 'api.example.com' }) })
    expect(within(question).getByText(tr('domains.list.confirm_remove_runs', { count: 2 }))).toBeTruthy()
    await user.click(within(question).getByRole('button', { name: i18n.t('common:actions.cancel') }))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull())
    expect(calls.some(call => call.method === 'POST')).toBe(false)
    await user.click(screen.getByRole('button', { name: tr('domains.list.remove_for', { host: 'api.example.com' }) }))
    question = await screen.findByRole('alertdialog')
    await user.click(within(question).getByRole('button', { name: tr('domains.list.remove') }))
    expect(calls.find(call => call.method === 'POST')).toEqual({ method: 'POST', path: '/api/domains/remove', action: 'remove-domain', body: { domain_id: VERIFIED.id } })
    expect(await screen.findByText(tr('domains.list.removed', { host: 'api.example.com' }))).toBeTruthy()
    expect(await screen.findByText(new RegExp(tr('domains.list.empty')))).toBeTruthy()
  })
})
