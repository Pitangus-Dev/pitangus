import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { DomainList } from '@/features/domains/domain-list'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const page = (items: unknown[]) => ({ items, total: items.length, limit: 20, dast: true })
const ID = 'a'.repeat(24)
const PENDING = { id: ID, host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: '', key: 'domain:app.example.com', verified: false, expired: false,
  registered_at: '2026-10-01T00:00:00Z', registered_by: 'jefa', verified_at: null, verified_until: null, checked_at: null, proof_method: null,
  txt_name: '_pitangus.app.example.com', txt_value: 'pitangus-verify=abc123', verify_token: 'abc123', verify_file_url: 'https://app.example.com/.well-known/pitangus-verify.txt',
  verify_meta: '<meta name="pitangus-verify" content="abc123">', schedule: null, headers: [], header_count: 0, runs: 0, open: 0, last_scan: null }
const VERIFIED = { ...PENDING, id: 'b'.repeat(24), host: 'api.example.com', key: 'domain:api.example.com', kind: 'api', verified: true, proof_method: 'file',
  verified_at: '2026-10-02T00:00:00Z', verified_until: '2026-12-31T00:00:00Z', runs: 2, open: 5, test_user_count: 2,
  schedule: { frequency: 'monthly', weekdays: [], month_days: [1], time: '09:00', timezone: 'UTC', next_run_at: '2026-11-01T09:00:00Z' },
  last_scan: { id: 'run-1', status: 'completed', created_at: '2026-10-05T00:00:00Z', finished_at: null, variant: 'api' } }

function render(admin = true, handler: Parameters<typeof mockApi>[0] = () => ({ body: page([PENDING, VERIFIED]) })) {
  const calls = mockApi(handler)
  const opened: [string, string | undefined][] = []
  const scans: string[] = []
  renderWithQueries(<DomainList admin={admin} onOpenDomain={(domain, tab) => opened.push([domain.id, tab])} onNewScan={domain => scans.push(domain.id)} />)
  return { calls, opened, scans, user: userEvent.setup() }
}

describe('domains list', () => {
  it('lists sites and APIs alike, with the kind as a tag, the proof, last scan and schedule, test users, and open findings', async () => {
    const { user, opened } = render()
    const table = await screen.findByRole('table')
    const columns = within(table).getAllByRole('columnheader').map(cell => cell.textContent)
    expect(columns.slice(0, 5)).toEqual([tr('domains.list.col_domain'), tr('domains.list.col_verification'), tr('domains.list.col_last_scan'), tr('domains.list.col_login'),
      tr('domains.list.col_open')])
    const verified = within(table).getAllByRole('row').find(row => row.textContent?.includes('api.example.com')) as HTMLElement
    expect(within(verified).getByText(tr('domains.kind.api'))).toBeTruthy()
    expect(within(verified).getAllByText(tr('domains.list.verified_by', { method: tr('domains.method.file') })).length).toBeGreaterThan(0)
    expect(within(verified).getByText(tr('domains.schedule.frequency.monthly'))).toBeTruthy()
    expect(screen.queryByText('domain:api.example.com')).toBeNull()
    await user.click(within(verified).getByRole('button', { name: tr('domains.list.open_for', { host: 'api.example.com', count: 5 }) }))
    await user.click(within(verified).getByRole('button', { name: 'api.example.com' }))
    await user.click(within(verified).getByRole('button', { name: tr('domains.list.login_for', { host: 'api.example.com', count: 2 }) }))
    expect(opened).toEqual([[VERIFIED.id, 'findings'], [VERIFIED.id, undefined], [VERIFIED.id, 'users']])
    const pending = within(table).getAllByRole('row').find(row => row.textContent?.includes('app.example.com')) as HTMLElement
    expect(within(pending).getAllByText(tr('domains.list.pending')).length).toBeGreaterThan(0)
    expect(within(pending).getByText(tr('domains.kind.web'))).toBeTruthy()
    expect(within(pending).getByText(tr('domains.list.never'))).toBeTruthy()
    expect(within(pending).getByText(tr('domains.list.login_none'))).toBeTruthy()
  })

  it('puts "Add domain" next to the title, searches the list and opens a domain from anywhere on its row', async () => {
    const { user, opened } = render()
    const title = await screen.findByRole('heading', { level: 1, name: i18n.t('nav:items.domains') })
    expect(title.parentElement?.parentElement?.querySelector('button')?.textContent).toBe(tr('domains.list.add'))
    expect(await screen.findByText(tr('domains.list.showing', { shown: 2, total: 2 }))).toBeTruthy()
    await user.type(screen.getByRole('searchbox', { name: tr('domains.list.search') }), 'api.')
    expect(screen.getByText(tr('domains.list.showing', { shown: 1, total: 2 }))).toBeTruthy()
    const rows = within(screen.getByRole('table')).getAllByRole('row')
    expect(rows).toHaveLength(2)  // the header and api.example.com
    await user.click(within(rows[1]).getByText(tr('domains.kind.api')))
    expect(opened).toEqual([[VERIFIED.id, undefined]])
    // Its own buttons keep their click: the menu opens, the row doesn't.
    await user.click(within(rows[1]).getByRole('button', { name: tr('domains.list.actions_for', { host: 'api.example.com' }) }))
    expect(opened).toHaveLength(1)
    await user.keyboard('{Escape}')
    await user.clear(screen.getByRole('searchbox', { name: tr('domains.list.search') }))
    await user.type(screen.getByRole('searchbox', { name: tr('domains.list.search') }), 'nothing-here')
    expect(screen.getByText(tr('domains.list.no_match', { query: 'nothing-here' }))).toBeTruthy()
  })

  it('shows an empty state with one action', async () => {
    render(true, () => ({ body: page([]) }))
    expect(await screen.findByText(tr('domains.list.empty_title'))).toBeTruthy()
    expect(screen.getAllByRole('button', { name: tr('domains.list.add') })).toHaveLength(1)
  })

  it('members read the list without actions or proofs', async () => {
    render(false, () => ({ body: page([{ ...VERIFIED, txt_name: null, txt_value: null, verify_token: null, verify_meta: null, verify_file_url: null, headers: null }]) }))
    expect(await screen.findByText('api.example.com')).toBeTruthy()
    expect(screen.getByText(tr('domains.list.read_only'))).toBeTruthy()
    expect(screen.queryByRole('button', { name: tr('domains.list.add') })).toBeNull()
    expect(screen.queryByRole('button', { name: tr('domains.list.actions_for', { host: 'api.example.com' }) })).toBeNull()
  })

  it('removing asks first and says what goes with it', async () => {
    let items: unknown[] = [VERIFIED]
    const { calls, user } = render(true, call => {
      if (call.method === 'GET') return { body: page(items) }
      if (call.path === '/api/domains/remove') { items = []; return { body: { id: VERIFIED.id, host: VERIFIED.host, runs_deleted: 2 } } }
    })
    await user.click(await screen.findByRole('button', { name: tr('domains.list.actions_for', { host: 'api.example.com' }) }))
    await user.click(await screen.findByRole('menuitem', { name: tr('domains.list.remove') }))
    const question = await screen.findByRole('alertdialog', { name: tr('domains.list.remove_title', { host: 'api.example.com' }) })
    expect(within(question).getByText(tr('domains.list.confirm_remove_runs', { count: 2 }))).toBeTruthy()
    await user.click(within(question).getByRole('button', { name: tr('domains.list.remove') }))
    await waitFor(() => expect(calls.find(call => call.method === 'POST')).toEqual({ method: 'POST', path: '/api/domains/remove', action: 'remove-domain', body: { domain_id: VERIFIED.id } }))
    expect(await screen.findByText(tr('domains.list.removed', { host: 'api.example.com' }))).toBeTruthy()
    expect(await screen.findByText(tr('domains.list.empty_title'))).toBeTruthy()
  })
})

describe('adding a domain', () => {
  it('probes the address while typing, then opens its verification', async () => {
    let items: unknown[] = []
    const { calls, user } = render(true, call => {
      if (call.method === 'GET') return { body: page(items) }
      if (call.path === '/api/domains/probe') return { body: { host: 'app.example.com', reachable: true, https: true, status: 'reachable', detail: 'ok', http_status: 200, public: true } }
      if (call.path === '/api/domains') { items = [PENDING]; return { body: PENDING } }
    })
    await user.click(await screen.findByRole('button', { name: tr('domains.list.add') }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(tr('domains.add.domain')), 'app.example.com')
    expect(await within(dialog).findByText(tr('domains.add.reachable', { code: 200 }), {}, { timeout: 3000 })).toBeTruthy()
    expect(calls.filter(call => call.path === '/api/domains/probe').map(call => [call.action, call.body])).toEqual([['probe-domain', { url: 'https://app.example.com' }]])
    await user.click(within(dialog).getByRole('button', { name: tr('domains.add.submit') }))
    expect(calls.find(call => call.method === 'POST' && call.path === '/api/domains')?.body).toEqual({ url: 'https://app.example.com', kind: 'web', context: '' })
    expect(await screen.findByRole('dialog', { name: tr('domains.verify.title', { host: 'app.example.com' }) })).toBeTruthy()
  })

  it("doesn't block a domain that doesn't answer", async () => {
    const { user } = render(true, call => {
      if (call.method === 'GET') return { body: page([]) }
      if (call.path === '/api/domains/probe') return { body: { host: 'app.example.com', reachable: false, https: false, status: 'unreachable', detail: 'No HTTPS response on port 443.', public: true } }
    })
    await user.click(await screen.findByRole('button', { name: tr('domains.list.add') }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText(tr('domains.add.domain')), 'app.example.com')
    expect(await within(dialog).findByText(tr('domains.add.unreachable'), { exact: false }, { timeout: 3000 })).toBeTruthy()
    expect(within(dialog).getByRole('button', { name: tr('domains.add.submit') }).hasAttribute('disabled')).toBe(false)
  })
})

describe('verifying a domain', () => {
  it('offers DNS, file and meta tabs and verifies with the one on screen', async () => {
    let attempts = 0
    const { calls, user, scans } = render(true, call => {
      if (call.method === 'GET') return { body: page([PENDING]) }
      if (call.path === '/api/domains/verify') {
        attempts += 1
        return attempts === 1 ? { status: 400, body: { error: 'The file has no token' } }
          : { body: { ...PENDING, verified: true, proof_method: 'file', verified_until: '2027-01-07T00:00:00Z' } }
      }
    })
    await user.click(await screen.findByRole('button', { name: tr('domains.list.actions_for', { host: 'app.example.com' }) }))
    await user.click(await screen.findByRole('menuitem', { name: tr('domains.list.verify') }))
    const dialog = await screen.findByRole('dialog', { name: tr('domains.verify.title', { host: 'app.example.com' }) })
    expect(within(dialog).getByRole('tab', { name: new RegExp(tr('domains.verify.tab_dns')) }).getAttribute('aria-selected')).toBe('true')
    expect(within(dialog).getByText(PENDING.txt_value)).toBeTruthy()
    expect(within(dialog).getByRole('button', { name: tr('domains.verify.copy', { field: tr('domains.verify.value') }) })).toBeTruthy()

    await user.click(within(dialog).getByRole('tab', { name: tr('domains.verify.tab_file') }))
    expect(await within(dialog).findByText(PENDING.verify_file_url)).toBeTruthy()
    expect(within(dialog).getByText(tr('domains.verify.exact_host', { host: 'app.example.com' }))).toBeTruthy()
    await user.click(within(dialog).getByRole('button', { name: tr('domains.verify.submit') }))
    const alert = await within(dialog).findByRole('alert')
    expect(alert.textContent).toContain(tr('domains.verify.failed_file', { url: PENDING.verify_file_url }))
    expect(alert.textContent).toContain('The file has no token')

    await user.click(within(dialog).getByRole('button', { name: tr('domains.verify.submit') }))
    expect(await within(dialog).findByText(tr('domains.verify.done', { host: 'app.example.com' }))).toBeTruthy()
    expect(calls.filter(call => call.path === '/api/domains/verify').map(call => call.body)).toEqual([{ domain_id: ID, method: 'file' }, { domain_id: ID, method: 'file' }])
    await user.click(within(dialog).getByRole('button', { name: tr('domains.verify.start_scan') }))
    await vi.waitFor(() => expect(scans).toEqual([ID]))
  })
})
