import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { formatDate } from '@/shared/i18n/format'
import type { SessionUser } from '@/features/auth/session'
import type { DomainTab } from '@/features/domains/domain-list'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { Domain } from '@/pages/Domain'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const ID = 'a'.repeat(24)
const DOMAIN = { id: ID, host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: 'Shop front', key: 'domain:app.example.com', verified: true, expired: false,
  registered_at: '2026-10-01T00:00:00Z', registered_by: 'jefa', verified_until: '2026-12-31T00:00:00Z', proof_method: 'meta', schedule: null, schedule_next_at: null,
  headers: [{ name: 'Cookie', last4: null, saved_at: '2026-10-02T00:00:00Z' }], header_count: 1, runs: 0, open: 0, last_scan: null }
const ADMIN = { username: 'jefa', display_name: 'Jefa', role: 'admin', totp_enabled: true } as unknown as SessionUser

function Page() {
  const [tab, setTab] = useState<DomainTab>('overview')
  return <Domain domainId={ID} tab={tab} onTab={setTab} user={ADMIN} onBack={() => {}} onNewScan={() => {}} onOpenRun={() => {}} onImport={() => {}} onOpenPolicies={() => {}} />
}

function setup() {
  let schedule: string | null = null
  const calls = mockApi(call => {
    if (call.path === '/api/domains' && call.method === 'GET') return { body: { items: [{ ...DOMAIN, schedule, schedule_next_at: schedule ? '2026-10-12T03:00:00Z' : null }], total: 1, limit: 20, dast: true } }
    if (call.path === '/api/domains/schedule') { schedule = (call.body as { schedule: string | null }).schedule; return { body: { ...DOMAIN, schedule } } }
    if (call.path === '/api/runs') return { body: [] }
    if (call.path.startsWith('/api/runs/page')) return { body: { items: [], total: 0, limit: 25, offset: 0 } }
    if (call.path.startsWith('/api/assets')) return { body: { items: [], total: 0, limit: 1, offset: 0 } }
    if (call.path === '/api/repositories/batches') return { body: { active: null, recent: [] } }
  })
  renderWithQueries(<Page />)
  return { calls, user: userEvent.setup() }
}

describe('a domain page', () => {
  it('has a heading, its proof and four tabs', async () => {
    const { user } = setup()
    expect(await screen.findByRole('heading', { level: 1, name: 'app.example.com' })).toBeTruthy()
    expect(screen.getByText(tr('domains.list.verified_by', { method: tr('domains.method.meta') }))).toBeTruthy()
    const tabs = screen.getAllByRole('tab').map(tab => tab.textContent)
    expect(tabs).toEqual([tr('domains.page.tabs.overview'), tr('domains.page.tabs.access'), tr('domains.page.tabs.findings'), tr('domains.page.tabs.scans')])
    // A meta proof covers the exact host only.
    expect(screen.getByText(tr('domains.page.scope_exact', { host: 'app.example.com' }))).toBeTruthy()
    expect(screen.getByText('Shop front')).toBeTruthy()

    await user.click(screen.getByRole('tab', { name: tr('domains.page.tabs.access') }))
    expect(await screen.findByRole('cell', { name: 'Cookie' })).toBeTruthy()
    await user.click(screen.getByRole('tab', { name: tr('domains.page.tabs.findings') }))
    expect(await screen.findByText(tr('domains.page.findings_empty'))).toBeTruthy()
    expect(screen.getByRole('button', { name: tr('domains.page.import_results') })).toBeTruthy()
    await user.click(screen.getByRole('tab', { name: tr('domains.page.tabs.scans') }))
    expect(await screen.findByText(tr('domains.page.scans_empty'))).toBeTruthy()
  })

  it('turns the weekly scan on and says when the next one is', async () => {
    const { calls, user } = setup()
    const toggle = await screen.findByRole('switch', { name: tr('domains.schedule.toggle') })
    expect(toggle.getAttribute('aria-checked')).toBe('false')
    await user.click(toggle)
    await waitFor(() => expect(calls.find(call => call.path === '/api/domains/schedule')).toEqual({ method: 'POST', path: '/api/domains/schedule', action: 'schedule-domain',
      body: { domain_id: ID, schedule: 'weekly' } }))
    await waitFor(() => expect(screen.getByRole('switch', { name: tr('domains.schedule.toggle') }).getAttribute('aria-checked')).toBe('true'))
    expect(await screen.findByText(tr('domains.schedule.next', { date: formatDate('2026-10-12T03:00:00Z') }))).toBeTruthy()
  })
})
