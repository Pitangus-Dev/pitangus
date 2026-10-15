import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import type { ScopedFindings } from '@/shared/api/queries'
import { ScopeResult } from '@/features/findings/scope-result'
import { groupFindings, type RepositoryFinding } from '@/features/findings/finding-model'

const SITE = { key: 'domain:pitangus.dev', name: 'pitangus.dev' }
const web = (rule: string, title: string, path: string, fingerprint: string, severity = 'medium'): RepositoryFinding => ({
  finding_id: fingerprint.slice(0, 16), fingerprint, scanner: 'dast', tool: 'zap', rule_id: rule, title, path, line: 1, severity, confidence: 7, verdict: 'candidate',
  cwe: [693], cve: [], ghsa: [], owasp: [], reason: 'ZAP reports it.', remediation: '', priority: { action: 'track', factors: [] }, triage: { status: 'open', history: [] },
  lifecycle: { status: 'open', origin: { kind: 'scan' } }, asset: { ...SITE, kind: 'domain' }, web: { method: 'GET' },
})
const CSP = 'CSP: style-src unsafe-inline'
const URLS = ['https://pitangus.dev/', 'https://pitangus.dev/es/', 'https://pitangus.dev/_astro']
const FINDINGS = [...URLS.map((url, index) => web('10055', CSP, url, `${'c'.repeat(63)}${index}`)), web('10096', 'Timestamp Disclosure - Unix', 'https://pitangus.dev/app.js', 'd'.repeat(64), 'low')]
const SCOPE = { id: 'scope', type: 'asset_scope', status: 'completed', created_at: '2026-10-10T00:00:00Z', total: 4, truncated: false, steps: [], limitations: [], owasp_coverage: [],
  summary: { lifecycle: { open: 4, fixed: 0, suppressed: 0, from_pr: 0, excluded: 0, unverified: 0, unverified_stale: 0, unverified_configuration: 0, by_severity: { critical: 0, high: 0, medium: 3, low: 1 } }, candidates: 4, sla: {},
    kpis: { active: 4, dismissed: 0, only_excluded: false, has_sla: false, overdue: 0, soon: 0, act: 0, attend: 0, critical: 0, high: 0, kev: 0, fixable: 0 } },
  by_asset: [{ ...SITE, kind: 'domain', open: 4, critical: 0, high: 0, fixed: 0, suppressed: 0, excluded: 0, shown: 4 }],
  findings: FINDINGS } as ScopedFindings
const tf = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)

describe('a web problem on several URLs', () => {
  it('is one group per rule and title, each URL still its own finding', () => {
    const groups = groupFindings(FINDINGS, i18n.t)
    expect(groups.map(group => [group.label, group.findings.length])).toEqual([[CSP, 3], ['Timestamp Disclosure - Unix', 1]])
    expect(groups[0].meta).toBe(tf('group.urls', { count: 3, value: '3' }))
    expect(new Set(groups[0].findings.map(item => item.fingerprint)).size).toBe(3)
    // Another rule with the same title, or the same rule elsewhere in another asset, isn't the same problem.
    const other: RepositoryFinding = { ...FINDINGS[0], fingerprint: 'e'.repeat(64), rule_id: '10038', asset: { key: 'domain:docs.pitangus.dev', name: 'docs', kind: 'domain' } }
    expect(groupFindings([...FINDINGS, other], i18n.t)).toHaveLength(3)
  })

  it('shows one row that opens to each URL, and says how many findings make how many problems', async () => {
    mockApi(() => undefined)
    renderWithQueries(<ScopeResult scope={SCOPE} name="pitangus.dev" tab="open" onChanged={() => {}} canAccept={false} onOpenAsset={() => {}} opening={{ pending: false, error: '' }} />)
    expect(screen.getByText(tf('table.grouped', { count: 2, problems: '2', findings: '4' }))).toBeTruthy()
    const row = screen.getByRole('button', { name: new RegExp(CSP.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) })
    expect(row.getAttribute('aria-expanded')).toBe('false')
    expect(row.textContent).toContain(tf('group.urls', { count: 3, value: '3' }))
    await userEvent.setup().click(row)
    expect(row.getAttribute('aria-expanded')).toBe('true')
    const region = document.getElementById(row.getAttribute('aria-controls') ?? '')
    expect(region).toBeTruthy()
    for (const url of URLS) expect(screen.getAllByText(url).length).toBeGreaterThan(0)
    // Every URL keeps its own triage: one entry each, under its own id.
    expect(region?.querySelectorAll('[id^="finding-"]').length).toBe(3)
  })
})
