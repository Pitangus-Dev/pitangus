import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { RepositoryResult } from '@/features/findings/repository-result'
import type { RepositoryFinding, RepositoryRun } from '@/features/findings/finding-model'

const FAMILY: RepositoryFinding = { finding_id: 'f1', fingerprint: 'a'.repeat(64), scanner: 'sast', tool: 'opengrep', rule_id: 'appsec.py.eval', title: 'eval on user input',
  path: 'app/views.py', line: 12, severity: 'high', confidence: 8, verdict: 'candidate', cwe: [95], cve: [], ghsa: [], owasp: [], reason: '', remediation: 'Avoid eval',
  count: 3, instances: [{ path: 'app/views.py', line: 12 }, { path: 'app/views.py', line: 40, unseen: true }] }
const RUN: RepositoryRun = { id: 'run-fam', type: 'repository_scan', status: 'completed', created_at: '2026-10-12T00:00:00Z',
  source: { name: 'org/api', provider: 'github' }, summary: { candidates: 1, severities: { high: 1 } }, findings: [FAMILY] }

describe('a family of copies', () => {
  it('says how many copies there are and where, and which one the last scan could not check', async () => {
    mockApi(() => undefined)
    const user = userEvent.setup()
    renderWithQueries(<RepositoryResult run={RUN} onNew={() => {}} onChanged={() => {}} canAccept />)
    await user.click(screen.getByRole('button', { name: /eval on user input/ }))
    await user.click(screen.getByText(i18n.t('findings:detail.copies', { count: 3 })))
    expect(screen.getByText('app/views.py:40')).toBeTruthy()
    expect(screen.getByText(new RegExp(i18n.t('findings:detail.copy_unverified')))).toBeTruthy()
    expect(screen.getByText(i18n.t('findings:detail.copies_more', { count: 1 }))).toBeTruthy()
  })
})
