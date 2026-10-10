import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { RepositoryResult } from '@/features/findings/repository-result'
import type { RepositoryFinding, RepositoryRun } from '@/features/findings/finding-model'

const POLICY = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
const CHECK = "curl -sI https://pitangus.dev/ | grep -i -E '^(content-security-policy):'"
const CSP: RepositoryFinding = { finding_id: 'w1', fingerprint: 'b'.repeat(64), scanner: 'dast', tool: 'ZAP', rule_id: '10055', title: 'CSP: style-src unsafe-inline',
  path: 'https://pitangus.dev/', line: 1, severity: 'medium', confidence: 6, verdict: 'candidate', cwe: [693], cve: [], ghsa: [], owasp: [],
  reason: 'ZAP reports: style-src includes unsafe-inline.', remediation: 'Guidance from ZAP: Ensure that your web server sets the header.',
  web: { method: 'GET', evidence: POLICY, description: 'Content Security Policy (CSP) is an added layer of security.', solution: 'Ensure that your web server sets the header.',
    references: ['https://www.w3.org/TR/CSP/', 'javascript:alert(1)'] },
  fix: { kind: 'web', steps: [], commands: [], example: null, web: { check: CHECK,
    highlight: { before: "default-src 'self'; style-src 'self' ", match: "'unsafe-inline'", after: "; frame-ancestors 'none'" } } },
  priority: { action: 'track', factors: ['Reported by ZAP, medium severity', "It's in the response headers"] },
  lifecycle: { status: 'open', origin: { kind: 'scan' }, first_seen: '2026-10-01T00:00:00Z' } }
const RUN: RepositoryRun = { id: 'run-web', type: 'dast_scan', status: 'completed', created_at: '2026-10-01T00:00:00Z', target: 'https://pitangus.dev/',
  source: { name: 'pitangus.dev', provider: 'domain' }, summary: { candidates: 1, severities: { medium: 1 } }, findings: [CSP] }

describe('web findings', () => {
  it('show what the scanner says, where, the highlighted evidence, the fix, a check and its references', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)
    renderWithQueries(<RepositoryResult run={RUN} onNew={() => {}} onChanged={() => {}} canAccept />)

    expect(screen.queryByText('https://pitangus.dev/:1')).toBeNull()
    await user.click(screen.getByRole('button', { name: /CSP: style-src unsafe-inline/ }))
    for (const key of ['web.what', 'web.where', 'web.evidence', 'web.how_to_fix', 'web.how_to_check']) {
      expect(screen.getByRole('heading', { name: new RegExp(`^${tr(key)}`) })).toBeTruthy()
    }
    expect(screen.getByText('Content Security Policy (CSP) is an added layer of security.')).toBeTruthy()
    expect(screen.getByText('ZAP reports: style-src includes unsafe-inline.')).toBeTruthy()
    expect(screen.getAllByText(new RegExp(tr('web.according_to', { tool: 'ZAP' }))).length).toBeGreaterThan(0)
    expect(screen.getByText("'unsafe-inline'").tagName).toBe('MARK')
    expect(screen.getAllByText('https://pitangus.dev/').length).toBeGreaterThan(1)  // the run's target, the row and the detail
    expect(screen.getByText('Ensure that your web server sets the header.')).toBeTruthy()
    expect(screen.getByText(CHECK)).toBeTruthy()
    expect(screen.getByText(tr('verify.prompt_web'))).toBeTruthy()
    const links = screen.getAllByRole('link').map(link => link.getAttribute('href'))
    expect(links).toContain('https://www.w3.org/TR/CSP/')
    expect(links).not.toContain('javascript:alert(1)')
  })

  it('still read well when stored before the scanner text was kept', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    const old = { ...CSP, web: { method: 'GET', evidence: POLICY }, fix: { kind: 'web' as const, steps: [], commands: [], example: null, web: { check: null, highlight: null } } }
    renderWithQueries(<RepositoryResult run={{ ...RUN, findings: [old] }} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /CSP: style-src unsafe-inline/ }))
    expect(screen.getByText('ZAP reports: style-src includes unsafe-inline.')).toBeTruthy()
    expect(screen.getByText('Guidance from ZAP: Ensure that your web server sets the header.')).toBeTruthy()
    // No check command: no "how to check" section; «Reverificar» below already says to re-scan.
    expect(screen.queryByText(i18n.t('findings:web.how_to_check'))).toBeNull()
  })
})
