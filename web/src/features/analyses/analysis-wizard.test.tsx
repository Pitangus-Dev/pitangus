import { describe, expect, it, onTestFinished, vi } from 'vitest'
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { AnalysisWizard } from '@/features/analyses/analysis-wizard'
import { browserZone } from '@/features/domains/schedule'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`analyses:${key}`, options)
const src = (key: string) => i18n.t(`sources:${key}`)
const SOURCE = { id: 'github#7', name: 'org/api', provider: 'github', branch: 'main', installation_id: 1 }
const PLAN = { languages: [{ name: 'Python', files: 12, rules: 40 }], runs: ['Opengrep'], skips: [], osv_needed: true, files: 12, manifests: ['setup.py'], iac: [] }
const DOMAIN = { id: 'a'.repeat(24), host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: '', key: 'domain:app.example.com',
  verified: true, expired: false, proof_method: 'dns', schedule: null, headers: [], header_count: 0, runs: 0, open: 0 }
const UNVERIFIED = { ...DOMAIN, id: 'b'.repeat(24), host: 'staging.example.com', url: 'https://staging.example.com/', key: 'domain:staging.example.com', verified: false, proof_method: null }
const API = { ...DOMAIN, id: 'c'.repeat(24), host: 'api.example.com', url: 'https://api.example.com/', kind: 'api', key: 'domain:api.example.com', proof_method: 'file',
  headers: [{ name: 'Authorization', last4: 'cret', saved_at: '2026-10-01T00:00:00Z' }], header_count: 1 }
type Related = { host: string; state: 'in_scope' | 'out_of_scope'; origin: 'discovered' | 'manual'; first_seen: string; last_seen: string | null }
const discovery = (status: string) => ({ status, requested_at: null, finished_at: status === 'done' ? '2026-10-09T00:00:00Z' : null, note: null,
  counts: status === 'done' ? { found: 3, kept: 1, private: 1, unresolved: 1, new: 1, capped: 0 } : null, available: true, unavailable: null })
const scopeOf = (hosts: Related[], status: string) => ({ domain_id: DOMAIN.id, root: DOMAIN.host, covered: true, reason: null, hosts,
  in_scope: hosts.filter(item => item.state === 'in_scope').length, limit: 100, scope_limit: 20, discovery: discovery(status) })
const SPEC = JSON.stringify({ openapi: '3.0.3', info: { title: 'Shop', version: '1' }, paths: { '/items': { get: {}, post: {} }, '/items/{id}': { parameters: [], get: {} } } })

function setup({ admin = true, dast = true, domains = [DOMAIN, UNVERIFIED] as unknown[], source = null as string | null } = {}) {
  // The domain's saved scope: never searched until the switch asks for it, then one public host found, out of scope.
  let related: Related[] = []
  let status = 'idle'
  const calls = mockApi(call => {
    if (call.path === '/api/domains') return { body: { items: domains, total: domains.length, limit: 20, dast } }
    if (call.path.startsWith('/api/domains/scope') && call.method === 'GET') return { body: scopeOf(related, status) }
    if (call.path === '/api/domains/discover') {
      status = 'done'
      related = [{ host: 'docs.app.example.com', state: 'out_of_scope', origin: 'discovered', first_seen: '2026-10-09T00:00:00Z', last_seen: '2026-10-09T00:00:00Z' }]
      return { status: 202, body: scopeOf(related, 'running') }
    }
    if (call.path === '/api/domains/scope') {
      const body = call.body as { op: string; host: string; state?: Related['state'] }
      if (body.op === 'add' && body.host.endsWith('.evil.com')) return { status: 400, body: { error: 'outside' } }
      if (body.op === 'add') related = [...related, { host: body.host, state: 'in_scope', origin: 'manual', first_seen: '2026-10-09T00:00:00Z', last_seen: null }]
      if (body.op === 'set') related = related.map(item => item.host === body.host ? { ...item, state: body.state ?? item.state } : item)
      return { body: scopeOf(related, status) }
    }
    if (call.path === '/api/domains/schedule') return { body: DOMAIN }
    if (call.path === '/api/domains/scans') return { status: 202, body: { run_id: 'run-web', run: { id: 'run-web', status: 'queued' }, domain: DOMAIN } }
    if (call.path.startsWith('/api/sources')) return { body: { sources: [SOURCE], total: 1 } }
    if (call.path.startsWith('/api/repositories/plan')) return { body: PLAN }
    if (call.path === '/api/repositories/batches') return { body: { active: null, recent: [] } }
    if (call.path === '/api/repositories/scans') return { body: { run: { id: 'run-9' } } }
    if (call.path === '/api/registries') return { body: { registries: [] } }
    if (call.path.startsWith('/api/assets')) return { body: { items: [], total: 0, limit: 1, offset: 0 } }
  })
  const done = vi.fn(async () => {})
  const scheduled = vi.fn()
  renderWithQueries(<AnalysisWizard onComplete={done} onBatchStarted={() => {}} onScheduled={scheduled} onManageConnections={() => {}} onCancel={() => {}} initialSourceId={source} isAdmin={admin} />)
  return { calls, done, scheduled, user: userEvent.setup() }
}
const proceed = (user: ReturnType<typeof userEvent.setup>) => user.click(screen.getByRole('button', { name: tr('wizard.continue') }))
const heading = (key: string) => screen.findByRole('heading', { level: 2, name: tr(key) })
const scan = (calls: Call[]) => calls.find(call => call.path === '/api/domains/scans')

describe('choosing what to scan', () => {
  it('offers three cards as one radio group, Code first, and moves with the arrow keys', async () => {
    const { user } = setup()
    const group = await screen.findByRole('radiogroup', { name: tr('chooser.title') })
    const cards = within(group).getAllByRole('radio')
    expect(cards.map(card => card.getAttribute('aria-checked'))).toEqual(['true', 'false', 'false'])
    // Sites and APIs are one type: no separate API card.
    expect(cards.map(card => card.getAttribute('aria-labelledby') && document.getElementById(card.getAttribute('aria-labelledby') as string)?.textContent))
      .toEqual([tr('wizard.kinds.code.title'), tr('wizard.kinds.image.title'), tr('wizard.kinds.web.title')])
    expect(screen.queryByText('Opengrep')).toBeNull()
    expect(screen.getByText(tr('wizard.kinds.web.line'))).toBeTruthy()
    cards[0].focus()
    await user.keyboard('{ArrowRight}')
    expect(screen.getByRole('radio', { name: tr('wizard.kinds.image.title') }).getAttribute('aria-checked')).toBe('true')
    await user.keyboard('{Enter}')
    expect(await heading('images.title')).toBeTruthy()
  })

  it('opens importing from its own link', async () => {
    const { user } = setup({ admin: false })
    await user.click(await screen.findByRole('button', { name: /SARIF/ }))
    expect(await screen.findByText(tr('import.title'))).toBeTruthy()
  })

  it('says web scans are off, and how an admin turns them on', async () => {
    setup({ dast: false })
    await waitFor(() => expect(screen.getByRole('radio', { name: tr('wizard.kinds.web.title') }).getAttribute('aria-disabled')).toBe('true'))
    expect(screen.getAllByText(tr('chooser.off'))).toHaveLength(1)
    expect(screen.getByText('PITANGUS_DAST_ENABLED=1')).toBeTruthy()
  })

  it('lets members read the web card but not continue', async () => {
    const { user } = setup({ admin: false })
    await user.click(await screen.findByRole('radio', { name: tr('wizard.kinds.web.title') }))
    expect(screen.getByRole('button', { name: tr('wizard.continue') }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByText(tr('chooser.admin_only'))).toBeTruthy()
  })
})

describe('a code scan', () => {
  async function toReview(user: ReturnType<typeof userEvent.setup>) {
    await screen.findByText(SOURCE.name)
    await proceed(user)
    await user.type(screen.getByLabelText(tr('context.label')), 'Public API behind the gateway')
    await proceed(user)
    await heading('review.title')
  }

  it('sends nothing to OSV unless the switch is turned on', async () => {
    const { user, calls, done } = setup({ admin: false, source: SOURCE.id })
    await toReview(user)
    expect((await screen.findAllByText(/Python/)).length).toBeGreaterThan(0)
    expect(screen.getByRole('switch', { name: tr('review.osv_label') }).getAttribute('aria-checked')).toBe('false')
    await user.click(screen.getByRole('button', { name: tr('launch.code') }))
    await vi.waitFor(() => expect(done).toHaveBeenCalledWith('run-9'))
    expect(calls.find(call => call.path === '/api/repositories/scans')?.body).toEqual({ source_id: SOURCE.id, allow_osv_upload: false, context: 'Public API behind the gateway' })
  })

  it('asks OSV only with the switch on', async () => {
    const { user, calls } = setup({ admin: false, source: SOURCE.id })
    await toReview(user)
    await user.click(await screen.findByRole('switch', { name: tr('review.osv_label') }))
    await user.click(screen.getByRole('button', { name: tr('launch.code') }))
    await vi.waitFor(() => expect(calls.find(call => call.path === '/api/repositories/scans')?.body).toMatchObject({ allow_osv_upload: true }))
  })

  it('skips the context without a warning and offers to add it from the review', async () => {
    const { user } = setup({ admin: false, source: SOURCE.id })
    await screen.findByText(SOURCE.name)
    await proceed(user)
    await user.click(screen.getByRole('button', { name: tr('wizard.skip') }))
    await heading('review.title')
    expect(screen.queryByRole('alertdialog')).toBeNull()
    await user.click(screen.getByRole('button', { name: i18n.t('analyses:review.no_context').replace(/.*<add>(.*)<\/add>.*/, '$1') }))
    expect(await heading('context.title')).toBeTruthy()
  })
})

describe('a web or API scan', () => {
  it('takes a verified domain, the scope saved on it (DNS proof) and warns before going without headers', async () => {
    const { user, calls, done } = setup()
    await user.click(await screen.findByRole('radio', { name: tr('wizard.kinds.web.title') }))
    await proceed(user)
    await heading('target.title')
    expect((await screen.findByRole('radio', { name: /staging\.example\.com/ })).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: tr('target.verify_for', { host: 'staging.example.com' }) })).toBeTruthy()
    expect(screen.getByRole('button', { name: tr('wizard.continue') }).hasAttribute('disabled')).toBe(true)
    await user.click(screen.getByRole('radio', { name: /app\.example\.com/ }))
    // A web domain keeps the API spec folded away.
    expect(screen.queryByLabelText(tr('spec.url_label'))).toBeNull()
    await user.click(screen.getByRole('button', { name: tr('spec.add') }))
    expect(document.activeElement).toBe(screen.getByRole('button', { name: tr('spec.choose') }))

    await user.click(screen.getByRole('switch', { name: tr('scope.toggle') }))
    expect(screen.getByText(tr('scope.toggle_hint'))).toBeTruthy()
    // Never searched: opening the scope starts the search, and what it finds starts excluded.
    expect(await screen.findByText(i18n.t('sources:domains.scope.root'))).toBeTruthy()
    const row = await screen.findByRole('radiogroup', { name: i18n.t('sources:domains.scope.row_label', { host: 'docs.app.example.com' }) })
    expect(calls.filter(call => call.path === '/api/domains/discover')).toEqual([{ method: 'POST', path: '/api/domains/discover', action: 'discover-domain', body: { domain_id: DOMAIN.id } }])
    expect(within(row).getByRole('radio', { name: i18n.t('sources:domains.scope.out') }).getAttribute('aria-checked')).toBe('true')
    await user.click(within(row).getByRole('radio', { name: i18n.t('sources:domains.scope.in') }))
    await waitFor(() => expect(calls.find(call => call.path === '/api/domains/scope' && call.method === 'POST')?.body)
      .toEqual({ domain_id: DOMAIN.id, op: 'set', host: 'docs.app.example.com', state: 'in_scope' }))
    await waitFor(() => expect(within(row).getByRole('radio', { name: i18n.t('sources:domains.scope.in') }).getAttribute('aria-checked')).toBe('true'))
    // A host typed by hand must be under the domain.
    await user.click(screen.getByRole('button', { name: i18n.t('sources:domains.scope.add') }))
    const field = screen.getByLabelText(i18n.t('sources:domains.scope.add_label', { domain: 'app.example.com' }))
    await user.type(field, 'evil.com{Enter}')
    expect(screen.getByText(i18n.t('sources:domains.scope.foreign', { host: 'evil.com', domain: 'app.example.com' }))).toBeTruthy()
    await user.clear(field)
    await user.type(field, 'shop.app.example.com{Enter}')
    const added = await screen.findByRole('radiogroup', { name: i18n.t('sources:domains.scope.row_label', { host: 'shop.app.example.com' }) })
    expect(within(added).getByRole('radio', { name: i18n.t('sources:domains.scope.in') }).getAttribute('aria-checked')).toBe('true')

    await proceed(user)
    await heading('access.title')
    await proceed(user)
    const question = await screen.findByRole('alertdialog', { name: tr('skip.access.title') })
    expect(within(question).getByText(tr('skip.access.text'))).toBeTruthy()
    await user.click(within(question).getByRole('button', { name: tr('skip.access.confirm') }))

    await heading('review.title')
    expect(screen.getByText(tr('review.scope_value', { host: 'app.example.com', count: 2 }))).toBeTruthy()
    expect(screen.getByText(tr('review.access_none'))).toBeTruthy()
    expect(screen.queryByText(tr('review.spec'))).toBeNull()
    expect(screen.getByText(tr('review.authorization'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('launch.web') }))
    await vi.waitFor(() => expect(done).toHaveBeenCalledWith('run-web'))
    expect(scan(calls)).toEqual({ method: 'POST', path: '/api/domains/scans', action: 'scan-domain',
      body: { domain_id: DOMAIN.id, mode: 'web', use_scope: true, use_headers: false } })
    expect(calls.some(call => call.path === '/api/domains/schedule')).toBe(false)
  })

  it('picks test users that sign in inside the scope, and offers to add one before going without any', async () => {
    const admin = { id: 'd'.repeat(24), name: 'Admin user', method: 'password', username: 'qa@app.example.com', applies_to: 'app.example.com', login_url: null }
    const docs = { id: 'e'.repeat(24), name: 'Docs editor', method: 'password_totp', username: 'docs', applies_to: 'docs.app.example.com', login_url: null }
    const { user, calls } = setup({ domains: [{ ...DOMAIN, test_users: [admin, docs], test_user_count: 2 }] })
    await user.click(await screen.findByRole('radio', { name: tr('wizard.kinds.web.title') }))
    await proceed(user)
    await user.click(await screen.findByRole('radio', { name: /app\.example\.com/ }))
    await proceed(user)
    await heading('access.title')
    await proceed(user)
    const question = await screen.findByRole('alertdialog', { name: tr('skip.access.title') })
    await user.click(within(question).getByRole('button', { name: tr('skip.access.back') }))
    expect(await screen.findByRole('dialog', { name: i18n.t('sources:domains.test_users.add_title') })).toBeTruthy()
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.cancel') }))

    // Docs signs in on a subdomain this scope doesn't reach.
    const outside = screen.getByRole('checkbox', { name: /Docs editor/ })
    expect(outside.hasAttribute('disabled')).toBe(true)
    expect(screen.getByText(tr('access.user_outside', { host: 'docs.app.example.com' }))).toBeTruthy()
    await user.click(screen.getByRole('checkbox', { name: /Admin user/ }))
    await proceed(user)
    await heading('review.title')
    expect(screen.getByText(tr('review.access_users', { names: 'Admin user' }))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('launch.web') }))
    await vi.waitFor(() => expect(scan(calls)).toBeTruthy())
    expect(scan(calls)?.body).toEqual({ domain_id: DOMAIN.id, mode: 'web', use_headers: false, test_users: [admin.id] })
  })

  it('jumps back to a step from its review row', async () => {
    const { user } = setup({ domains: [DOMAIN] })
    await user.click(await screen.findByRole('radio', { name: tr('wizard.kinds.web.title') }))
    await proceed(user)
    await user.click(await screen.findByRole('radio', { name: /app\.example\.com/ }))
    await proceed(user)
    await heading('access.title')
    await user.click(screen.getByRole('button', { name: tr('wizard.skip') }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: tr('skip.access.confirm') }))
    await heading('review.title')
    await user.click(screen.getByRole('button', { name: tr('review.change_for', { label: tr('review.access') }) }))
    expect(await heading('access.title')).toBeTruthy()
  })

  it('schedules the scan: also now by default, or only from then on', async () => {
    const reach = async (user: ReturnType<typeof userEvent.setup>) => {
      await user.click(await screen.findByRole('radio', { name: tr('wizard.kinds.web.title') }))
      await proceed(user)
      await user.click(await screen.findByRole('radio', { name: /app\.example\.com/ }))
      await proceed(user)
      await heading('access.title')
      await user.click(screen.getByRole('button', { name: tr('wizard.skip') }))
      await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: tr('skip.access.confirm') }))
      await heading('review.title')
    }
    // Noon UTC: in any zone, 23:45 local is still ahead.
    vi.useFakeTimers({ toFake: ['Date'], now: new Date('2026-10-09T12:00:00Z') })
    onTestFinished(() => { vi.useRealTimers() })
    const first = setup({ domains: [DOMAIN] })
    await reach(first.user)
    const toggle = screen.getByRole('switch', { name: src('domains.schedule.switch') })
    expect(toggle.getAttribute('aria-checked')).toBe('false')
    expect(screen.queryByRole('radiogroup', { name: src('domains.schedule.frequency.label') })).toBeNull()
    await first.user.click(toggle)
    await first.user.click(screen.getByRole('radio', { name: src('domains.schedule.frequency.daily') }))
    fireEvent.change(screen.getByLabelText(src('domains.schedule.time')), { target: { value: '23:45' } })
    const alsoNow = screen.getByRole('checkbox', { name: src('domains.schedule.also_now') }) as HTMLInputElement
    expect(alsoNow.checked).toBe(true)
    // Scanned now, the first scheduled scan waits for tomorrow.
    expect(screen.getByText(src('domains.schedule.once_a_day'))).toBeTruthy()
    await first.user.click(screen.getByRole('button', { name: tr('launch.web') }))
    await vi.waitFor(() => expect(first.done).toHaveBeenCalledWith('run-web'))
    const paths = first.calls.filter(call => call.method === 'POST').map(call => call.path)
    expect(paths).toEqual(['/api/domains/scans', '/api/domains/schedule'])  // the schedule after the scan, so it skips today
    expect(first.calls.find(call => call.path === '/api/domains/schedule')?.body).toEqual({ domain_id: DOMAIN.id,
      schedule: { frequency: 'daily', weekdays: [], month_days: [], time: '23:45', timezone: browserZone() } })
    cleanup()

    const second = setup({ domains: [DOMAIN] })
    await reach(second.user)
    await second.user.click(screen.getByRole('switch', { name: src('domains.schedule.switch') }))
    await second.user.click(screen.getByRole('checkbox', { name: src('domains.schedule.also_now') }))
    await second.user.click(screen.getByRole('button', { name: tr('launch.schedule') }))
    await vi.waitFor(() => expect(second.scheduled).toHaveBeenCalledWith(DOMAIN.id))
    expect(second.calls.some(call => call.path === '/api/domains/scans')).toBe(false)
    expect(second.done).not.toHaveBeenCalled()
    expect(second.calls.find(call => call.path === '/api/domains/schedule')?.body).toMatchObject({ domain_id: DOMAIN.id, schedule: { frequency: 'weekly', time: '09:00' } })
  })

  it('on an API domain, nudges for the spec, keeps a file proof to its exact host and sends the spec and saved headers', async () => {
    const { user, calls } = setup({ domains: [API] })
    await user.click(await screen.findByRole('radio', { name: tr('wizard.kinds.web.title') }))
    await proceed(user)
    await user.click(await screen.findByRole('radio', { name: /api\.example\.com/ }))
    expect(screen.queryByRole('switch', { name: tr('scope.toggle') })).toBeNull()
    expect(screen.getByText(tr('scope.exact_only', { host: 'api.example.com' }))).toBeTruthy()
    expect(screen.getByText(tr('spec.nudge'))).toBeTruthy()

    await user.upload(document.getElementById('spec-file') as HTMLInputElement, new File(['{"swagger": "1.0"}'], 'old.json', { type: 'application/json' }))
    expect(await screen.findByText(tr('spec.invalid'))).toBeTruthy()
    await user.upload(document.getElementById('spec-file') as HTMLInputElement, new File([SPEC], 'openapi.json', { type: 'application/json' }))
    expect(await screen.findByText(new RegExp(tr('spec.summary', { version: '3.0.3', count: 3 })))).toBeTruthy()
    expect(screen.queryByText(tr('spec.nudge'))).toBeNull()
    expect(screen.getByText(tr('spec.instead'))).toBeTruthy()
    // One source at a time: the URL waits while a file is loaded.
    expect((screen.getByLabelText(tr('spec.url_label')) as HTMLInputElement).disabled).toBe(true)
    await proceed(user)

    await heading('access.title')
    expect(screen.getByRole('switch', { name: tr('access.use_all') }).getAttribute('aria-checked')).toBe('true')
    expect(screen.getByText(tr('access.test_account'))).toBeTruthy()
    await proceed(user)
    await heading('review.title')
    expect(screen.getByText(new RegExp(`openapi\\.json · ${tr('spec.summary', { version: '3.0.3', count: 3 })}`))).toBeTruthy()
    expect(screen.getByText(tr('review.access_value', { count: 1, names: 'Authorization' }))).toBeTruthy()
    expect(screen.getByText(tr('review.schedule_without_spec'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('launch.web') }))
    await vi.waitFor(() => expect(scan(calls)).toBeTruthy())
    expect(scan(calls)?.body).toEqual({ domain_id: API.id, mode: 'api', use_headers: true, spec: { filename: 'openapi.json', content_base64: btoa(SPEC) } })
  })

  it('refuses a spec URL outside the scope, allows none, and sends one in scope', async () => {
    const { user, calls } = setup({ domains: [API] })
    await user.click(await screen.findByRole('radio', { name: tr('wizard.kinds.web.title') }))
    await proceed(user)
    await user.click(await screen.findByRole('radio', { name: /api\.example\.com/ }))
    const url = screen.getByLabelText(tr('spec.url_label'))
    await user.type(url, 'https://evil.com/openapi.json')
    expect(screen.getByText(tr('spec.url_foreign', { host: 'api.example.com' }))).toBeTruthy()
    expect(screen.getByRole('button', { name: tr('wizard.continue') }).hasAttribute('disabled')).toBe(true)
    await user.clear(url)
    // Nothing given: still a valid scan, of what the crawler can reach.
    expect(screen.getByRole('button', { name: tr('wizard.continue') }).hasAttribute('disabled')).toBe(false)
    await user.type(url, 'https://api.example.com/openapi.json')
    await proceed(user)
    await heading('access.title')
    await proceed(user)
    await heading('review.title')
    await user.click(screen.getByRole('button', { name: tr('launch.web') }))
    await vi.waitFor(() => expect(scan(calls)?.body).toEqual({ domain_id: API.id, mode: 'api', use_headers: true, spec_url: 'https://api.example.com/openapi.json' }))
  })
})
