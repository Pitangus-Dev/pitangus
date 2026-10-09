import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import type { ScopedFindings } from '@/shared/api/queries'
import { ScopeResult } from '@/features/findings/scope-result'
import type { RepositoryFinding } from '@/features/findings/finding-model'

const PRINT = 'a'.repeat(64)
const finding = (asset: { key: string; name: string }, severity: string, title: string): RepositoryFinding => ({
  finding_id: `${asset.key}-f`, fingerprint: PRINT, scanner: 'sast', rule_id: 'rule', title, path: 'app.py', line: 1, severity, confidence: 8, verdict: 'candidate',
  cwe: [], cve: [], ghsa: [], owasp: [], reason: '', remediation: '', priority: { action: 'attend', factors: [] }, triage: { status: 'open', history: [] },
  lifecycle: { status: 'open', origin: { kind: 'scan' } }, asset: { ...asset, kind: 'repository' },
})
const API = { key: 'github#1', name: 'org/api' }
const WEB = { key: 'github#2', name: 'org/web' }
// The same fingerprint in two repositories: two findings, one row each.
const SCOPE = { id: 'scope', type: 'asset_scope', status: 'completed', created_at: '2026-10-01T00:00:00Z', total: 2, truncated: false, steps: [], limitations: [], owasp_coverage: [],
  summary: { lifecycle: { open: 2, fixed: 0, suppressed: 0, from_pr: 0, excluded: 0, by_severity: { critical: 1, high: 1, medium: 0, low: 0 } }, candidates: 2, sla: {},
    kpis: { active: 2, dismissed: 0, only_excluded: false, has_sla: false, overdue: 0, soon: 0, act: 0, attend: 2, critical: 1, high: 1, kev: 0, fixable: 0 } },
  by_asset: [{ ...API, kind: 'repository', open: 1, critical: 1, high: 0, fixed: 0, suppressed: 0, excluded: 0, shown: 1 },
    { ...WEB, kind: 'repository', open: 1, critical: 0, high: 1, fixed: 0, suppressed: 0, excluded: 0, shown: 1 }],
  findings: [finding(API, 'critical', 'eval in api'), finding(WEB, 'high', 'eval in web')] } as ScopedFindings
const tf = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)
const JIRA = { configured: true, site: 'https://acme.atlassian.net', email: 'sec@acme.test', last4: 'abcd', destinations: 1, rules: 1, automatic: false }

function render(onOpenAsset = vi.fn()) {
  renderWithQueries(<ScopeResult scope={SCOPE} name="org" tab="open" onChanged={() => {}} canAccept={false} onOpenAsset={onOpenAsset} opening={{ pending: false, error: '' }} />)
  return onOpenAsset
}
async function selectBoth() {
  const user = userEvent.setup()
  await user.click(screen.getByRole('checkbox', { name: tf('table.select_item', { name: 'eval in api · org/api' }) }))
  await user.click(screen.getByRole('checkbox', { name: tf('table.select_item', { name: 'eval in web · org/web' }) }))
  return user
}

describe('findings of several assets', () => {
  it('adds up the scope, lists each asset and opens one', async () => {
    mockApi(() => undefined)
    const opened = render()
    expect(screen.getByRole('heading', { name: 'org' })).toBeTruthy()
    const byAsset = screen.getByRole('region', { name: tf('scope.by_asset.title') })
    expect(within(byAsset).getByText(tf('scope.by_asset.critical', { count: 1, value: '1' }))).toBeTruthy()
    // Each row says its asset; per-asset files aren't offered, the consolidated audit evidence is.
    expect(screen.getAllByText('org/web').length).toBeGreaterThan(1)
    expect(screen.queryByRole('button', { name: tf('export.pdf') })).toBeNull()
    expect(screen.getByText(tf('scope.exports_one'))).toBeTruthy()
    await userEvent.setup().click(within(byAsset).getByRole('button', { name: /org\/web/ }))
    expect(opened).toHaveBeenCalledWith('github#2')
  })

  it('triages a selection across assets in one request, and says which assets failed', async () => {
    const calls = mockApi(call => call.path === '/api/findings/triage'
      ? { body: { results: (call.body as { selections: { run_id: string }[] }).selections.map(part => part.run_id === 'asset:github#2' ? { run_id: part.run_id, error: 'Some fingerprints are not in this run.' } : { run_id: part.run_id }) } }
      : undefined)
    render()
    const user = await selectBoth()
    expect(screen.getByText(tf('scope.selected', { count: 2, value: '2', assets: '2' }))).toBeTruthy()
    await user.click(screen.getAllByRole('button', { name: new RegExp(tf('triage.verb.fixed')) })[0])
    await user.type(screen.getByLabelText(tf('triage.reason')), 'Patched in both services')
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.save') }))

    const sent = () => calls.filter(call => call.path === '/api/findings/triage').map(call => call.body)
    await vi.waitFor(() => expect(sent()).toHaveLength(1))
    expect(sent()[0]).toEqual({ selections: [{ run_id: 'asset:github#1', fingerprints: [PRINT] }, { run_id: 'asset:github#2', fingerprints: [PRINT] }],
      status: 'fixed', reason: 'Patched in both services' })
    const alert = await screen.findByText(tf('scope.triage_partial', { count: 1, total: 2 }))
    expect(alert.parentElement?.textContent).toContain('org/web · Some fingerprints are not in this run.')
    // A retry sends only what failed.
    await user.click(screen.getByRole('button', { name: tf('scope.triage_retry', { count: 1 }) }))
    await vi.waitFor(() => expect(sent()).toHaveLength(2))
    expect((sent()[1] as { selections: unknown[] }).selections).toEqual([{ run_id: 'asset:github#2', fingerprints: [PRINT] }])
  })

  it('sends a Jira selection per asset', async () => {
    const calls = mockApi(call => call.path === '/api/integrations/jira' ? { body: JIRA }
      : call.path === '/api/integrations/jira/issues' ? { body: { created: [], existing: [], failed: [] } } : undefined)
    render()
    const user = await selectBoth()
    await user.click(await screen.findByRole('button', { name: i18n.t('findings:selection.jira') }))
    await user.click(await screen.findByRole('button', { name: i18n.t('integrations:jira.export.submit', { count: 2 }) }))
    await vi.waitFor(() => expect(calls.some(call => call.path === '/api/integrations/jira/issues')).toBe(true))
    expect(calls.find(call => call.path === '/api/integrations/jira/issues')?.body).toEqual({
      selections: [{ asset: 'github#1', fingerprints: [PRINT] }, { asset: 'github#2', fingerprints: [PRINT] }] })
  })
})
