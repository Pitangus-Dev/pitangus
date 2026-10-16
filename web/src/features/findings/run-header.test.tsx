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

  it('names the tools that ran, leaving out the skipped ones', () => {
    const steps = [{ id: 'dast-katana', name: 'Crawl (katana)', status: 'completed', detail: '' }, { id: 'dast', name: 'ZAP', status: 'completed', detail: '' },
      { id: 'dast-nuclei', name: 'nuclei', status: 'partial', detail: '' }, { id: 'dast-testssl', name: 'testssl.sh', status: 'skipped', detail: '' },
      { id: 'dast-merge', name: 'One finding per problem', status: 'completed', detail: '' }]
    render(<RunHeader run={{ ...RUN, steps }} onNew={() => {}} />)
    expect(screen.getByText(tr('web.eyebrow', { tools: 'ZAP + katana + nuclei' }))).toBeTruthy()
  })

  it('says nothing about sign-in for an anonymous scan, nor partial coverage when every sign-in worked', () => {
    const { unmount } = render(<RunHeader run={RUN} onNew={() => {}} />)
    expect(screen.queryByRole('list', { name: tr('web.sign_ins') })).toBeNull()
    unmount()
    render(<RunHeader run={{ ...RUN, logins: [{ name: 'Admin', status: 'signed_in' }] }} onNew={() => {}} />)
    expect(screen.queryByText(tr('web.partial'))).toBeNull()
  })
})

describe('asset state header', () => {
  const state = (id: string): RepositoryRun => ({ id: `asset:${id}`, type: 'asset_state', status: 'completed', created_at: '2026-10-10T00:00:00Z',
    source: { id, name: id, provider: '' }, summary: {} })

  it('words a domain, an image and a repository each its own way', () => {
    const { unmount } = render(<RunHeader run={state('domain:pitangus.dev')} onNew={() => {}} />)
    expect(screen.getByText(tr('state.eyebrow', { provider: tr('state.provider.domain') }))).toBeTruthy()
    expect(screen.getByText(tr('state.help_domain'))).toBeTruthy()
    expect(screen.queryByText(tr('state.help'))).toBeNull()
    unmount()
    const image = render(<RunHeader run={state('image:ghcr.io/acme/api')} onNew={() => {}} />)
    expect(screen.getByText(tr('state.eyebrow', { provider: tr('state.provider.registry') }))).toBeTruthy()
    expect(screen.getByText(tr('state.help_image'))).toBeTruthy()
    image.unmount()
    render(<RunHeader run={state('github#1')} onNew={() => {}} />)
    expect(screen.getByText(tr('state.eyebrow', { provider: tr('state.provider.repository') }))).toBeTruthy()
    expect(screen.getByText(tr('state.help'))).toBeTruthy()
  })
})

describe('current state header', () => {
  it('counts the unverified apart, so the header adds up to what the open tab lists', () => {
    const lifecycle = { open: 16, fixed: 14, suppressed: 2, from_pr: 0, excluded: 0, unverified: 3, by_severity: {} }
    render(<RunHeader run={{ ...RUN, type: 'asset_state', source: { id: 'github#1', name: 'org/api', provider: 'github' }, summary: { lifecycle } }} onNew={() => {}} />)
    const line = screen.getByText(content => content.includes(tr('state.unverified', { count: 3 })))
    expect(line.textContent).toContain('16')
    expect(line.textContent).toContain('14')
  })
})
