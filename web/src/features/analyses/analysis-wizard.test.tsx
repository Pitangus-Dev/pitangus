import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { AnalysisWizard } from '@/features/analyses/analysis-wizard'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`analyses:${key}`, options)
const SOURCE = { id: 'github#7', name: 'org/api', provider: 'github', branch: 'main', installation_id: 1 }
const PLAN = { languages: [{ name: 'Python', files: 12, rules: 40 }], runs: ['Opengrep'], skips: [], osv_needed: true, files: 12, manifests: ['setup.py'], iac: [] }
const DOMAIN = { id: 'a'.repeat(24), host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: '', key: 'domain:app.example.com',
  verified: true, expired: false, proof_method: 'dns', schedule: null, headers: [], header_count: 0, runs: 0, open: 0 }
const UNVERIFIED = { ...DOMAIN, id: 'b'.repeat(24), host: 'staging.example.com', url: 'https://staging.example.com/', key: 'domain:staging.example.com', verified: false, proof_method: null }
const API = { ...DOMAIN, id: 'c'.repeat(24), host: 'api.example.com', url: 'https://api.example.com/', kind: 'api', key: 'domain:api.example.com', proof_method: 'file',
  headers: [{ name: 'Authorization', last4: 'cret', saved_at: '2026-10-01T00:00:00Z' }], header_count: 1 }
const SPEC = JSON.stringify({ openapi: '3.0.3', info: { title: 'Shop', version: '1' }, paths: { '/items': { get: {}, post: {} }, '/items/{id}': { parameters: [], get: {} } } })

function setup({ admin = true, dast = true, domains = [DOMAIN, UNVERIFIED] as unknown[], source = null as string | null } = {}) {
  const calls = mockApi(call => {
    if (call.path === '/api/domains') return { body: { items: domains, total: domains.length, limit: 20, dast } }
    if (call.path === '/api/domains/scans') return { status: 202, body: { run_id: 'run-web', run: { id: 'run-web', status: 'queued' }, domain: DOMAIN } }
    if (call.path.startsWith('/api/sources')) return { body: { sources: [SOURCE], total: 1 } }
    if (call.path.startsWith('/api/repositories/plan')) return { body: PLAN }
    if (call.path === '/api/repositories/batches') return { body: { active: null, recent: [] } }
    if (call.path === '/api/repositories/scans') return { body: { run: { id: 'run-9' } } }
    if (call.path === '/api/registries') return { body: { registries: [] } }
    if (call.path.startsWith('/api/assets')) return { body: { items: [], total: 0, limit: 1, offset: 0 } }
  })
  const done = vi.fn(async () => {})
  renderWithQueries(<AnalysisWizard onComplete={done} onBatchStarted={() => {}} onManageConnections={() => {}} onCancel={() => {}} initialSourceId={source} isAdmin={admin} />)
  return { calls, done, user: userEvent.setup() }
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
  it('takes a verified domain, a scope with subdomains (DNS proof) and warns before going without headers', async () => {
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
    const field = screen.getByLabelText(tr('scope.add_label'))
    await user.type(field, 'evil.com{Enter}')
    expect(screen.getByText(tr('scope.foreign', { host: 'evil.com', domain: 'app.example.com' }))).toBeTruthy()
    await user.clear(field)
    await user.type(field, 'shop.app.example.com{Enter}')
    const row = screen.getByRole('radiogroup', { name: tr('scope.row_label', { host: 'shop.app.example.com' }) })
    expect(within(row).getByRole('radio', { name: tr('scope.in') }).getAttribute('aria-checked')).toBe('true')

    await proceed(user)
    await heading('access.title')
    await proceed(user)
    const question = await screen.findByRole('alertdialog', { name: tr('skip.access.title') })
    expect(within(question).getByText(tr('skip.access.text'))).toBeTruthy()
    await user.click(within(question).getByRole('button', { name: tr('skip.access.confirm') }))

    await heading('review.title')
    expect(screen.getByText(tr('review.scope_value', { host: 'app.example.com', count: 1 }))).toBeTruthy()
    expect(screen.getByText(tr('review.access_none'))).toBeTruthy()
    expect(screen.queryByText(tr('review.spec'))).toBeNull()
    expect(screen.getByText(tr('review.authorization'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('launch.web') }))
    await vi.waitFor(() => expect(done).toHaveBeenCalledWith('run-web'))
    expect(scan(calls)).toEqual({ method: 'POST', path: '/api/domains/scans', action: 'scan-domain',
      body: { domain_id: DOMAIN.id, mode: 'web', hosts: ['shop.app.example.com'], use_headers: false } })
    expect(calls.some(call => call.path === '/api/domains/schedule')).toBe(false)
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
