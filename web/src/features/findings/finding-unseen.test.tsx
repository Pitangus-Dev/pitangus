import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { RepositoryResult } from '@/features/findings/repository-result'
import type { RepositoryFinding, RepositoryRun } from '@/features/findings/finding-model'

const SECRET: RepositoryFinding = { finding_id: 's1', fingerprint: 'b'.repeat(64), scanner: 'secrets', tool: 'betterleaks', rule_id: 'generic-password',
  title: 'Password in code', path: 'config/settings.py', line: 4, severity: 'critical', confidence: 8, verdict: 'candidate', cwe: [798], cve: [], ghsa: [],
  owasp: [], reason: '', remediation: 'Rotate it',
  lifecycle: { status: 'open', origin: { kind: 'scan' }, unseen: { since: '2026-10-12T00:00:00Z', scans: 1, reason: 'configuration', cause: 'rule_off',
    rule: 'generic-password', engine: 'betterleaks' } } }
const RUN = (finding: RepositoryFinding): RepositoryRun => ({ id: 'asset:github#7', type: 'repository_scan', status: 'completed', created_at: '2026-10-12T00:00:00Z',
  source: { name: 'org/api', provider: 'github' }, summary: { candidates: 1, severities: { critical: 1 } }, findings: [finding] })

describe('an unverified finding', () => {
  it('names the rule a configuration change turned off, and the engine one turned off', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    const { unmount } = renderWithQueries(<RepositoryResult run={RUN(SECRET)} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /Password in code/ }))
    expect(screen.getByText('generic-password', { selector: 'code' })).toBeTruthy()
    unmount()
    const engineOff = { ...SECRET, lifecycle: { ...SECRET.lifecycle!, unseen: { ...SECRET.lifecycle!.unseen!, cause: 'engine_off' as const, engine: 'checkov' } } }
    renderWithQueries(<RepositoryResult run={RUN(engineOff)} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /Password in code/ }))
    expect(screen.getAllByText(/Checkov/).length).toBeGreaterThan(0)
  })

  it('says a secret stays open while its file still has one it cannot be told apart from', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    const unidentified = { ...SECRET, lifecycle: { ...SECRET.lifecycle!, unseen: { since: '2026-10-12T00:00:00Z', scans: 1, reason: 'unidentified' } } }
    renderWithQueries(<RepositoryResult run={RUN(unidentified)} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /Password in code/ }))
    expect(screen.getByText(/couldn't be read for certain/)).toBeTruthy()
  })
})
