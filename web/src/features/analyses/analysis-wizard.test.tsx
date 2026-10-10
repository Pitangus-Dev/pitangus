import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { AnalysisWizard } from '@/features/analyses/analysis-wizard'

const SOURCE = { id: 'github#7', name: 'org/api', provider: 'github', branch: 'main', installation_id: 1 }
const PLAN = { languages: [{ name: 'Python', files: 12, rules: 40 }], runs: ['Opengrep'], skips: [], osv_needed: true, files: 12,
  manifests: ['setup.py'], iac: [] }

function wizard(onComplete: (id: string) => Promise<void>) {
  const calls = mockApi(call => {
    if (call.path.startsWith('/api/sources')) return { body: { sources: [SOURCE], total: 1 } }
    if (call.path.startsWith('/api/repositories/plan')) return { body: PLAN }
    if (call.path === '/api/repositories/batches') return { body: { active: null, recent: [] } }
    if (call.path === '/api/repositories/scans') return { body: { run: { id: 'run-9' } } }
  })
  renderWithQueries(<AnalysisWizard onComplete={onComplete} onBatchStarted={() => {}} onManageConnections={() => {}} onManageDomains={() => {}} onCancel={() => {}}
    initialSourceId={SOURCE.id} isAdmin={false} />)
  return calls
}

const VERIFIED = { id: 'a'.repeat(24), host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: '', key: 'domain:app.example.com',
  verified: true, expired: false, runs: 0, open: 0 }
const UNVERIFIED = { ...VERIFIED, id: 'b'.repeat(24), host: 'staging.example.com', url: 'https://staging.example.com/', key: 'domain:staging.example.com', verified: false }

function webWizard(page: { dast: boolean }, admin: boolean) {
  return mockApi(call => {
    if (call.path === '/api/domains') return { body: { items: [VERIFIED, UNVERIFIED], total: 2, limit: 20, ...page } }
    if (call.path === '/api/domains/scans') return admin ? { status: 202, body: { run: { id: 'run-web', status: 'queued' }, domain: VERIFIED } } : { status: 403, body: { error: 'no' } }
    if (call.path === '/api/repositories/batches') return { body: { active: null, recent: [] } }
    if (call.path === '/api/registries') return { body: { registries: [] } }
  })
}

async function toReview(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText(SOURCE.name)
  await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }))
  await user.type(screen.getByLabelText(new RegExp(i18n.t('analyses:context.question'))), 'Public API behind the gateway')
  await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }))
  await screen.findByRole('checkbox')
}

describe('launching an analysis', () => {
  it('sends nothing to OSV unless the person agrees', async () => {
    const done = vi.fn(async () => {})
    const user = userEvent.setup()
    const calls = wizard(done)
    await toReview(user)
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:launch.code')) }))

    await vi.waitFor(() => expect(done).toHaveBeenCalledWith('run-9'))
    expect(calls.find(call => call.path === '/api/repositories/scans')).toEqual({ method: 'POST', path: '/api/repositories/scans',
      action: 'scan-repository', body: { source_id: SOURCE.id, allow_osv_upload: false, context: 'Public API behind the gateway' } })
  })

  it('asks OSV only with the consent ticked', async () => {
    const user = userEvent.setup()
    const calls = wizard(async () => {})
    await toReview(user)
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:launch.code')) }))
    await vi.waitFor(() => expect(calls.some(call => call.path === '/api/repositories/scans')).toBe(true))
    const scan = calls.find(call => call.path === '/api/repositories/scans')
    expect(scan?.body).toMatchObject({ allow_osv_upload: true })
  })

  it('launches a passive web scan of a verified domain, never of an unverified one', async () => {
    const calls = webWizard({ dast: true }, true)
    const done = vi.fn(async () => {})
    const user = userEvent.setup()
    renderWithQueries(<AnalysisWizard onComplete={done} onBatchStarted={() => {}} onManageConnections={() => {}} onManageDomains={() => {}} onCancel={() => {}}
      initialSourceId={null} isAdmin />)
    expect(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.kinds.api.title')) }).hasAttribute('disabled')).toBe(true)
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.kinds.web.title')) }))
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }))

    const unverified = await screen.findByRole('radio', { name: new RegExp('staging.example.com') })
    expect(unverified.hasAttribute('disabled')).toBe(true)
    const next = screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) })
    expect(next.hasAttribute('disabled')).toBe(true)
    await user.click(screen.getByRole('radio', { name: new RegExp('app.example.com') }))
    await user.click(next)
    expect(await screen.findByText(i18n.t('analyses:review.web_skips.attacks'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:launch.web')) }))

    await vi.waitFor(() => expect(done).toHaveBeenCalledWith('run-web'))
    expect(calls.find(call => call.path === '/api/domains/scans')).toEqual({ method: 'POST', path: '/api/domains/scans', action: 'scan-domain',
      body: { domain_id: VERIFIED.id } })
  })

  it('says how to turn web scans on, and that only administrators launch them', async () => {
    webWizard({ dast: false }, false)
    const user = userEvent.setup()
    renderWithQueries(<AnalysisWizard onComplete={async () => {}} onBatchStarted={() => {}} onManageConnections={() => {}} onManageDomains={() => {}} onCancel={() => {}}
      initialSourceId={null} isAdmin={false} />)
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.kinds.web.title')) }))
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }))

    expect(await screen.findByText('PITANGUS_DAST_ENABLED=1')).toBeTruthy()
    expect(screen.getByText(i18n.t('analyses:web.admin_only'))).toBeTruthy()
    await user.click(screen.getByRole('radio', { name: new RegExp('app.example.com') }))
    expect(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }).hasAttribute('disabled')).toBe(true)
  })

  it('offers importing SARIF next to the scan types', async () => {
    mockApi(call => call.path.startsWith('/api/assets') ? { body: { items: [], total: 0, limit: 1, offset: 0 } } : undefined)
    const user = userEvent.setup()
    renderWithQueries(<AnalysisWizard onComplete={async () => {}} onBatchStarted={() => {}} onManageConnections={() => {}} onManageDomains={() => {}} onCancel={() => {}}
      initialSourceId={null} isAdmin={false} />)
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:run_type.sarif_import')) }))
    await user.click(screen.getByRole('button', { name: new RegExp(i18n.t('analyses:wizard.continue')) }))

    expect(await screen.findByText(i18n.t('analyses:import.title'))).toBeTruthy()
    expect(await screen.findByText(i18n.t('analyses:import.no_asset'))).toBeTruthy()
  })
})
