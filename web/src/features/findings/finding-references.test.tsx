import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { RepositoryResult } from '@/features/findings/repository-result'
import type { RepositoryFinding, RepositoryRun } from '@/features/findings/finding-model'

const REFERENCES = ['https://github.com/advisories/GHSA-aaaa', 'https://exa mple.com/broken', 'javascript:alert(1)']
const DEPENDENCY: RepositoryFinding = { finding_id: 'd1', fingerprint: 'b'.repeat(64), scanner: 'sca', tool: 'trivy', rule_id: 'GHSA-aaaa', title: 'Prototype pollution in lodash',
  path: 'package-lock.json', line: 0, severity: 'high', confidence: 9, verdict: 'candidate', cwe: [], cve: [], ghsa: ['GHSA-aaaa'], owasp: [], reason: '', remediation: 'Upgrade',
  package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm', fixed_version: '4.17.21' } as RepositoryFinding['package'],
  advisory: { id: 'GHSA-aaaa', aliases: [], summary: 'Prototype pollution in lodash', details: '', cvss_vector: null, cvss_score: null, published: null, modified: null, references: REFERENCES },
  source: { id: 'osv', name: 'OSV', url: 'javascript:alert(1)', license: 'CC-BY-4.0', terms: 'attribution' } }
const RUN: RepositoryRun = { id: 'run-refs', type: 'repository_scan', status: 'completed', created_at: '2026-10-17T00:00:00Z',
  source: { name: 'org/web', provider: 'github' }, summary: { candidates: 1, severities: { high: 1 } }, findings: [DEPENDENCY] }

describe('advisory references', () => {
  it('links only valid http(s) references and shows the rest as text, without breaking the detail', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    renderWithQueries(<RepositoryResult run={RUN} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /lodash 4\.17\.20.*advisory/ }))
    const advisory = screen.queryByRole('button', { name: /Prototype pollution in lodash/ })
    if (advisory) await user.click(advisory)
    const link = screen.getByRole('link', { name: /github\.com/ })
    expect(link.getAttribute('href')).toBe('https://github.com/advisories/GHSA-aaaa')
    expect(screen.getByText('https://exa mple.com/broken').tagName).toBe('SPAN')
    expect(screen.getByText('javascript:alert(1)').tagName).toBe('SPAN')
    expect(document.querySelectorAll('a[href^="javascript:"]').length).toBe(0)
    expect(screen.getByText(/OSV · CC-BY-4\.0/)).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'OSV' })).toBeNull()  // a source URL that isn't http(s) isn't a link either
  })
})
