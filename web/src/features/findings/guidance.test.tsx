import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { RepositoryResult } from '@/features/findings/repository-result'
import type { RepositoryFinding, RepositoryRun } from '@/features/findings/finding-model'

const CSP_SHEET = 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'
const CSP: RepositoryFinding = { finding_id: 'w1', fingerprint: 'b'.repeat(64), scanner: 'dast', tool: 'ZAP', rule_id: '10038', title: 'Content Security Policy Header Not Set',
  path: 'https://pitangus.dev/', line: 1, severity: 'medium', confidence: 6, verdict: 'candidate', cwe: [693], cve: [], ghsa: [], owasp: ['A06:2025'],
  reason: '', remediation: 'Guidance from ZAP', web: { method: 'GET', description: 'CSP is an added layer of security.', solution: 'Set the header.', references: ['https://www.w3.org/TR/CSP/'] },
  guidance: [{ title: 'Content Security Policy Cheat Sheet', url: CSP_SHEET, kind: 'cheatsheet' },
    { title: 'A06:2025 Insecure Design', url: 'https://top10.owasp.org/2025/A06_2025-Insecure_Design/', kind: 'top10' },
    { title: 'Not a page', url: 'javascript:alert(1)', kind: 'cheatsheet' }],
  lifecycle: { status: 'open', origin: { kind: 'scan' }, first_seen: '2026-10-01T00:00:00Z' } }
const RUN: RepositoryRun = { id: 'run-web', type: 'dast_scan', status: 'completed', created_at: '2026-10-01T00:00:00Z', target: 'https://pitangus.dev/',
  source: { name: 'pitangus.dev', provider: 'domain' }, summary: { candidates: 1, severities: { medium: 1 } }, findings: [CSP] }

describe('OWASP guidance', () => {
  it('links the OWASP pages after the tool references, in a new tab that says so', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    renderWithQueries(<RepositoryResult run={RUN} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /Content Security Policy Header Not Set/ }))

    const section = screen.getByRole('region', { name: new RegExp(`^${i18n.t('findings:guidance.title')}`) })
    const links = within(section).getAllByRole('link')
    expect(links.map(link => link.getAttribute('href'))).toEqual([CSP_SHEET, 'https://top10.owasp.org/2025/A06_2025-Insecure_Design/'])
    for (const link of links) {
      expect(link.getAttribute('target')).toBe('_blank')
      expect(link.getAttribute('rel')).toBe('noreferrer')
      expect(link.textContent).toContain(i18n.t('findings:guidance.new_tab'))
    }
    expect(within(section).getByText('Content Security Policy Cheat Sheet')).toBeTruthy()
    const all = screen.getAllByRole('link').map(link => link.getAttribute('href'))
    expect(all.indexOf('https://www.w3.org/TR/CSP/')).toBeLessThan(all.indexOf(CSP_SHEET))  // the tool's own references first
  })

  it('show nothing without guidance', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    renderWithQueries(<RepositoryResult run={{ ...RUN, findings: [{ ...CSP, guidance: undefined }] }} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /Content Security Policy Header Not Set/ }))
    expect(screen.queryByRole('region', { name: new RegExp(`^${i18n.t('findings:guidance.title')}`) })).toBeNull()
  })
})
