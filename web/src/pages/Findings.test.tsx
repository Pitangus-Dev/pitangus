import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call, type Reply } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import type { SessionUser } from '@/features/auth/session'
import type { Asset } from '@/features/sources/asset-option'
import type { RepositoryFinding } from '@/features/findings/finding-model'
import { Findings } from '@/pages/Findings'

const tf = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)
const ADMIN: SessionUser = { id: '1', username: 'ana', display_name: 'Ana', role: 'admin', totp_enabled: false, last_login_at: null }
const asset = (key: string, name: string): Asset => ({ key, name, provider: 'github', scans: 1, pr_reviews: 0, last_activity: '2026-10-01T00:00:00Z', removed_at: null,
  latest_scan: null, open: { total: 1, critical: 0, high: 1, medium: 0, low: 0 } })
const API = asset('github#1', 'org/api')
const WEB = asset('github#2', 'org/web')
const finding = (title: string): RepositoryFinding => ({ finding_id: title, fingerprint: 'a'.repeat(64), scanner: 'sast', rule_id: 'rule', title, path: 'app.py', line: 1,
  severity: 'high', confidence: 8, verdict: 'candidate', cwe: [], cve: [], ghsa: [], owasp: [], reason: '', remediation: '', priority: { action: 'attend', factors: [] },
  triage: { status: 'open', history: [] }, lifecycle: { status: 'open', origin: { kind: 'scan' } } })
const detail = (id: string, of: Asset, title: string, extra: Record<string, unknown> = {}) => ({ id, type: 'asset_state', status: 'completed', created_at: '2026-10-01T00:00:00Z',
  source: { id: of.key, uid: of.key, name: of.name, provider: 'github' }, steps: [], limitations: [], owasp_coverage: [], findings: [finding(title)],
  summary: { candidates: 1, lifecycle: { open: 1, fixed: 2, suppressed: 0, from_pr: 0, excluded: 0, by_severity: {} },
    kpis: { active: 1, dismissed: 0, only_excluded: false, has_sla: false, overdue: 0, soon: 0, act: 0, attend: 1, critical: 0, high: 1, kev: 0, fixable: 0 } }, ...extra })
const RUN = { ...detail('run-1', API, 'eval in the old scan'), type: 'repository_scan' }

// The panel's other calls (session-wide queries) answered with empty but well-formed bodies.
function serve(routes: (call: Call) => Reply | undefined) {
  return mockApi(call => routes(call) ?? (call.path.startsWith('/api/evidence') ? { body: { accounts: [], assets: 2 } }
    : call.path.startsWith('/api/assets/exclusions') ? { body: { patterns: [], reason: null, by: null, at: null } }
    : call.path.startsWith('/api/assets/secrets') ? { body: { rules: [], disabled_rules: [], allowlist: { regexes: [], paths: [], stopwords: [] }, defaults: { rules: 0, disabled: 0, allowlist: 0 } } }
    : call.path.startsWith('/api/integrations/jira/issues/batches') ? { body: { items: [] } }
    : call.path.startsWith('/api/integrations/jira') ? { body: { configured: false } }
    : call.path.startsWith('/api/findings/scope') ? { status: 500, body: { error: 'not expected' } }
    : undefined))
}
const assets = (call: Call) => call.path === '/api/assets?key=github%231&limit=1' ? { body: { items: [API], total: 1 } }
  : call.path === '/api/assets?key=github%232&limit=1' ? { body: { items: [WEB], total: 1 } }
  : call.path === '/api/assets?limit=1' ? { body: { items: [API], total: 2 } } : undefined
const states = (call: Call) => call.path.startsWith('/api/assets/state') ? call : null
const page = (requestedRun: string | null = null) => renderWithQueries(<Findings user={ADMIN} requestedRun={requestedRun} onNew={() => {}} onOpenPolicies={() => {}} />)

beforeEach(() => { window.location.hash = '#/findings' })
afterEach(() => { window.location.hash = '' })

describe('one asset\'s findings', () => {
  it('opens on the requested run, found by its asset\'s identity', async () => {
    const calls = serve(call => assets(call) ?? (call.path === '/api/runs/run-1' ? { body: RUN } : undefined))
    page('run-1')
    expect(await screen.findByText('eval in the old scan')).toBeTruthy()
    expect(screen.getByRole('button', { name: `${tf('page.asset')}: org/api` })).toBeTruthy()
    expect(screen.getByRole('button', { name: new RegExp(`^${tf('page.run')}: ${tf('page.kind_scan')} · `) })).toBeTruthy()
    expect(calls.filter(states)).toEqual([])
    // Fetched once on arrival and reused by the view; the asset once, by its key.
    expect(calls.filter(call => call.path === '/api/runs/run-1').length).toBeLessThanOrEqual(2)
    expect(calls.filter(call => call.path.startsWith('/api/assets?'))).toHaveLength(1)
    await waitFor(() => expect(window.location.hash).toBe('#/findings?repo=github%231&run=run-1'))
  })

  it('opens on the asset in the address, at its current state', async () => {
    const calls = serve(call => assets(call) ?? (call.path === '/api/assets/state?key=github%232&status=open' ? { body: detail('state:github#2', WEB, 'eval in web') } : undefined))
    window.location.hash = '#/findings?repo=github%232'
    page()
    expect(await screen.findByText('eval in web')).toBeTruthy()
    expect(screen.getByRole('button', { name: `${tf('page.run')}: ${tf('page.current')}` })).toBeTruthy()
    expect(calls.filter(states)).toHaveLength(1)
  })

  it('says there is nothing yet when no asset was analyzed', async () => {
    serve(call => call.path === '/api/assets?limit=1' ? { body: { items: [], total: 0 } } : undefined)
    page()
    expect(await screen.findByText(tf('page.empty'))).toBeTruthy()
  })

  it('switches to one of the asset\'s runs and back to the tabs', async () => {
    serve(call => assets(call)
      ?? (call.path.startsWith('/api/assets/state?key=github%231&status=open') ? { body: detail('state:github#1', API, 'eval now') }
      : call.path.startsWith('/api/assets/state?key=github%231&status=fixed') ? { body: detail('state:github#1', API, 'eval fixed') }
      : call.path.startsWith('/api/runs/page') ? { body: { items: [RUN], total: 1, limit: 50, offset: 0 } }
      : call.path === '/api/runs/run-1' ? { body: RUN } : undefined))
    const user = userEvent.setup()
    page()
    expect(await screen.findByText('eval now')).toBeTruthy()

    await user.click(screen.getByRole('button', { name: new RegExp(`^${tf('page.tabs.fixed')} · `) }))
    expect(await screen.findByText('eval fixed')).toBeTruthy()

    await user.click(screen.getByRole('button', { name: `${tf('page.run')}: ${tf('page.current')}` }))
    await user.click(await screen.findByRole('option', { name: new RegExp(tf('page.kind_scan')) }))
    expect(await screen.findByText('eval in the old scan')).toBeTruthy()
    expect(screen.queryByRole('button', { name: new RegExp(`^${tf('page.tabs.fixed')} · `) })).toBeNull()
    await waitFor(() => expect(window.location.hash).toContain('run=run-1'))
  })

  it('says when the assets could not be loaded instead of claiming there are none', async () => {
    let fail = true
    serve(call => call.path === '/api/assets?limit=1' ? (fail ? { status: 500, body: { error: 'database is down' } } : { body: { items: [API], total: 1 } })
      : call.path.startsWith('/api/assets/state') ? { body: detail('state:github#1', API, 'eval now') } : assets(call))
    const user = userEvent.setup()
    page()
    expect((await screen.findByRole('alert')).textContent).toContain(tf('page.assets_failed', { error: 'database is down' }))
    expect(screen.queryByText(tf('page.empty'))).toBeNull()
    fail = false
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.retry') }))
    expect(await screen.findByText('eval now')).toBeTruthy()
  })

  it('says when the findings could not be loaded, and tries again', async () => {
    let fail = true
    serve(call => assets(call) ?? (call.path.startsWith('/api/assets/state') ? (fail ? { status: 500, body: { error: 'database is down' } } : { body: detail('state:github#1', API, 'eval now') }) : undefined))
    const user = userEvent.setup()
    page()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain(tf('page.load_failed', { error: 'database is down' }))
    fail = false
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.retry') }))
    expect(await screen.findByText('eval now')).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('reloads the state after a triage decision', async () => {
    let title = 'eval now'
    const calls = serve(call => assets(call)
      ?? (call.path.startsWith('/api/assets/state') ? { body: detail('state:github#1', API, title) }
      : call.path === '/api/findings/triage' ? (title = 'eval after triage', { body: {} }) : undefined))
    const user = userEvent.setup()
    page()
    await user.click(await screen.findByRole('button', { name: /eval now/ }))
    await user.click(screen.getByRole('button', { name: tf('triage.verb.fixed') }))
    await user.type(await screen.findByLabelText(tf('triage.reason')), 'Upgraded in the last release')
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.save') }))
    expect(await screen.findByText('eval after triage')).toBeTruthy()
    expect(calls.filter(states)).toHaveLength(2)
  })
})
