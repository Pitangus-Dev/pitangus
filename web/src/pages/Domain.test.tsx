import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { formatDay } from '@/shared/i18n/format'
import type { SessionUser } from '@/features/auth/session'
import type { DomainTab } from '@/features/domains/domain-list'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { Domain } from '@/pages/Domain'
import { browserZone, describeRule, formatRun, weekdayName } from '@/features/domains/schedule'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const ID = 'a'.repeat(24)
const DOMAIN = { id: ID, host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: 'Shop front', key: 'domain:app.example.com', verified: true, expired: false,
  registered_at: '2026-10-01T00:00:00Z', registered_by: 'jefa', verified_until: '2026-12-31T00:00:00Z', proof_method: 'meta', schedule: null,
  headers: [{ name: 'Cookie', last4: null, saved_at: '2026-10-02T00:00:00Z' }], header_count: 1, runs: 0, open: 0, last_scan: null }
const ADMIN = { username: 'jefa', display_name: 'Jefa', role: 'admin', totp_enabled: true } as unknown as SessionUser

function Page() {
  const [tab, setTab] = useState<DomainTab>('overview')
  return <Domain domainId={ID} tab={tab} onTab={setTab} user={ADMIN} onBack={() => {}} onNewScan={() => {}} onOpenRun={() => {}} onImport={() => {}} onOpenPolicies={() => {}} />
}

const SCOPE = { domain_id: ID, root: 'app.example.com', covered: false, reason: 'Verify with DNS to include subdomains', in_scope: 0, limit: 100, scope_limit: 20,
  hosts: [{ host: 'docs.app.example.com', state: 'out_of_scope', origin: 'discovered', first_seen: '2026-10-09T00:00:00Z', last_seen: '2026-10-09T00:00:00Z' }],
  discovery: { status: 'done', requested_at: null, finished_at: '2026-10-09T00:00:00Z', note: null, counts: { found: 4, kept: 1, private: 2, unresolved: 1, new: 1, capped: 0 },
    available: true, unavailable: null } }

function setup(extra: Record<string, unknown> = {}) {
  let schedule: Record<string, unknown> | null = null
  const calls = mockApi(call => {
    if (call.path.startsWith('/api/domains/scope') || call.path === '/api/domains/discover') return { body: SCOPE }
    if (call.path === '/api/domains' && call.method === 'GET') return { body: { items: [{ ...DOMAIN, ...extra, schedule }], total: 1, limit: 20, dast: true } }
    if (call.path === '/api/domains/schedule') {
      const rule = (call.body as { schedule: Record<string, unknown> | null }).schedule
      schedule = rule && { ...rule, next_run_at: '2026-10-16T14:00:00Z' }
      return { body: { ...DOMAIN, schedule } }
    }
    if (call.path === '/api/runs') return { body: [] }
    if (call.path.startsWith('/api/runs/page')) return { body: { items: [], total: 0, limit: 25, offset: 0 } }
    if (call.path.startsWith('/api/assets')) return { body: { items: [], total: 0, limit: 1, offset: 0 } }
    if (call.path === '/api/repositories/batches') return { body: { active: null, recent: [] } }
  })
  renderWithQueries(<Page />)
  return { calls, user: userEvent.setup() }
}

describe('a domain page', () => {
  it('has a heading, its kind and proof in one line, and five tabs with headers in the overview', async () => {
    const { user } = setup()
    expect(await screen.findByRole('heading', { level: 1, name: 'app.example.com' })).toBeTruthy()
    expect(screen.getByText(tr('domains.kind.web'))).toBeTruthy()
    expect(screen.getByText(tr('domains.list.verified_by', { method: tr('domains.method.meta') }))).toBeTruthy()
    expect(screen.getByText(tr('domains.page.until', { date: formatDay('2026-12-31T00:00:00Z', { dateStyle: 'medium' }) }))).toBeTruthy()
    const tabs = screen.getAllByRole('tab').map(tab => tab.textContent)
    expect(tabs).toEqual([tr('domains.page.tabs.overview'), tr('domains.page.tabs.findings'), tr('domains.page.tabs.scans'), tr('domains.page.tabs.scope'), tr('domains.page.tabs.users')])
    // A meta proof covers the exact host only, and says so where it matters.
    expect(screen.getByText(tr('domains.page.scope_exact', { host: 'app.example.com' }))).toBeTruthy()
    expect(screen.getByRole('button', { name: tr('domains.page.verify_dns') })).toBeTruthy()
    expect(screen.getByText('Shop front')).toBeTruthy()
    expect(screen.getByRole('heading', { level: 2, name: tr('domains.page.access_title') })).toBeTruthy()
    expect(within(screen.getByRole('list', { name: tr('domains.access.list_label') })).getByText('Cookie')).toBeTruthy()

    await user.click(screen.getByRole('tab', { name: tr('domains.page.tabs.findings') }))
    expect(await screen.findByText(tr('domains.page.findings_empty'))).toBeTruthy()
    expect(screen.getByRole('button', { name: tr('domains.page.import_results') })).toBeTruthy()
    await user.click(screen.getByRole('tab', { name: tr('domains.page.tabs.scans') }))
    expect(await screen.findByText(tr('domains.page.scans_empty'))).toBeTruthy()
  })

  it('lists related hosts in the Scope tab, disabled with the reason while the proof covers only the exact host', async () => {
    const { calls, user } = setup()
    await user.click(await screen.findByRole('tab', { name: tr('domains.page.tabs.scope') }))
    const row = await screen.findByRole('radiogroup', { name: tr('domains.scope.row_label', { host: 'docs.app.example.com' }) })
    expect(row.getAttribute('aria-disabled')).toBe('true')
    expect(within(row).getAllByRole('radio').every(radio => radio.hasAttribute('disabled'))).toBe(true)
    expect(screen.getByText('Verify with DNS to include subdomains')).toBeTruthy()
    expect(screen.getByText(tr('domains.scope.last_search', { date: formatDay('2026-10-09T00:00:00Z', { dateStyle: 'medium' }), kept: 1, count: 4 }))).toBeTruthy()
    expect(screen.queryByRole('button', { name: tr('domains.scope.add') })).toBeNull()
    expect(screen.getAllByRole('button', { name: tr('domains.page.verify_dns') }).length).toBeGreaterThan(0)
    await user.click(screen.getByRole('button', { name: tr('domains.scope.search_again') }))
    await waitFor(() => expect(calls.some(call => call.path === '/api/domains/discover' && call.action === 'discover-domain')).toBe(true))
  })

  it('ends the overview with a disconnect section that says what is deleted, and asks before doing it', async () => {
    const { calls, user } = setup()
    const zone = await screen.findByRole('region', { name: tr('domains.disconnect.title') })
    for (const key of ['domains.disconnect.headers', 'domains.disconnect.users', 'domains.disconnect.scope', 'domains.disconnect.schedule', 'domains.disconnect.final']) {
      expect(within(zone).getByText(tr(key))).toBeTruthy()
    }
    // Only in that section: the page's menu keeps verifying.
    await user.click(screen.getByRole('button', { name: tr('domains.list.actions_for', { host: 'app.example.com' }) }))
    expect(screen.queryByRole('menuitem', { name: tr('domains.list.remove') })).toBeNull()
    await user.keyboard('{Escape}')
    await user.click(within(zone).getByRole('button', { name: tr('domains.disconnect.button') }))
    const question = await screen.findByRole('alertdialog', { name: tr('domains.list.remove_title', { host: 'app.example.com' }) })
    expect(within(question).getByText(tr('domains.list.confirm_remove'))).toBeTruthy()
    await user.click(within(question).getByRole('button', { name: i18n.t('common:actions.cancel') }))
    expect(calls.some(call => call.path === '/api/domains/remove')).toBe(false)
  })

  it('schedules the scan, says when in plain words, and changes or turns it off', async () => {
    const { calls, user } = setup()
    expect(await screen.findByRole('heading', { level: 2, name: tr('domains.schedule.title') })).toBeTruthy()
    expect(screen.getByText(tr('domains.schedule.none'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('domains.schedule.set') }))
    expect(document.activeElement).toBe(screen.getByRole('radio', { name: tr('domains.schedule.frequency.weekly') }))
    // Weekly on today's weekday at 9:00 in the browser's zone, until changed.
    const days = screen.getByRole('group', { name: tr('domains.schedule.weekdays') })
    const pressed = within(days).getAllByRole('button').filter(button => button.getAttribute('aria-pressed') === 'true')
    expect(pressed).toHaveLength(1)
    await user.click(pressed[0])
    expect(screen.getByRole('button', { name: tr('domains.schedule.save') })).toHaveProperty('disabled', true)
    await user.click(within(days).getByRole('button', { name: weekdayName(5) }))
    await user.click(screen.getByRole('button', { name: tr('domains.schedule.save') }))
    await waitFor(() => expect(calls.find(call => call.path === '/api/domains/schedule')).toEqual({ method: 'POST', path: '/api/domains/schedule', action: 'schedule-domain',
      body: { domain_id: ID, schedule: { frequency: 'weekly', weekdays: [5], month_days: [], time: '09:00', timezone: browserZone(), test_users: [], use_headers: false } } }))
    // Testing Library collapses the narrow no-break space Intl puts before AM/PM.
    const sentence = describeRule({ frequency: 'weekly', weekdays: [5], month_days: [], time: '09:00', timezone: browserZone() }).replace(/\s/g, ' ')
    expect(await screen.findByText(sentence)).toBeTruthy()
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: tr('domains.schedule.change') })))
    expect(screen.getByText(tr('domains.schedule.next', { date: formatRun('2026-10-16T14:00:00Z') }))).toBeTruthy()

    await user.click(screen.getByRole('button', { name: tr('domains.schedule.change') }))
    await user.click(screen.getByRole('radio', { name: tr('domains.schedule.frequency.daily') }))
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.cancel') }))
    expect(screen.getByText(sentence)).toBeTruthy()

    await user.click(screen.getByRole('button', { name: tr('domains.schedule.turn_off') }))
    await waitFor(() => expect(calls.filter(call => call.path === '/api/domains/schedule').at(-1)?.body).toEqual({ domain_id: ID, schedule: null }))
    expect(await screen.findByText(tr('domains.schedule.none'))).toBeTruthy()
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: tr('domains.schedule.set') })))
  })

  it('shows the technologies the last web scan named, with their versions and when', async () => {
    const technologies = { run_id: 'r1', created_at: '2026-10-10T00:00:00Z', items: [{ name: 'Cloudflare', hosts: ['app.example.com'] },
      { name: 'Nginx', version: '1.27.5', hosts: ['app.example.com'] }] }
    setup({ last_scan: { id: 'r1', status: 'completed', created_at: '2026-10-10T00:00:00Z', technologies } })
    const list = await screen.findByRole('list', { name: tr('domains.page.technologies') })
    expect(within(list).getAllByRole('listitem').map(item => item.textContent)).toEqual(['Cloudflare', 'Nginx1.27.5'])
    expect(screen.getByText(tr('domains.page.technologies_seen', { date: formatDay('2026-10-10T00:00:00Z', { dateStyle: 'medium' }) }))).toBeTruthy()
  })
})
