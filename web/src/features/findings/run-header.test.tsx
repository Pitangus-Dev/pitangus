import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import i18n from '@/shared/i18n'
import { RunHeader } from '@/features/findings/run-header'
import type { RepositoryRun } from '@/features/findings/finding-model'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)
const RUN: RepositoryRun = { id: 'r1', type: 'dast_scan', status: 'completed', created_at: '2026-10-10T00:00:00Z', target: 'https://app.example.com/',
  source: { name: 'app.example.com', provider: 'domain' }, summary: {} }

describe('web scan header', () => {
  it('says who it signed in as, and that coverage is partial when a sign-in failed', () => {
    const reason = 'its check page https://app.example.com/account answered 302 instead of 200.'
    render(<RunHeader run={{ ...RUN, status: 'incomplete', logins: [{ name: 'Admin', status: 'signed_in', reason: null }, { name: 'Viewer', status: 'failed', reason }] }} onNew={() => {}} />)
    const list = screen.getByRole('list', { name: tr('web.sign_ins') })
    expect(within(list).getByText(tr('web.signed_in', { name: 'Admin' }))).toBeTruthy()
    expect(within(list).getByText(tr('web.sign_in_failed', { name: 'Viewer', reason }))).toBeTruthy()
    expect(screen.getByText(tr('web.partial'))).toBeTruthy()
  })

  it('says nothing about sign-in for an anonymous scan, nor partial coverage when every sign-in worked', () => {
    const { unmount } = render(<RunHeader run={RUN} onNew={() => {}} />)
    expect(screen.queryByRole('list', { name: tr('web.sign_ins') })).toBeNull()
    unmount()
    render(<RunHeader run={{ ...RUN, logins: [{ name: 'Admin', status: 'signed_in' }] }} onNew={() => {}} />)
    expect(screen.queryByText(tr('web.partial'))).toBeNull()
  })
})
