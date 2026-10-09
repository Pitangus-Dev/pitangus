import { afterEach, describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { GitHubInstall, type GitHubStatus } from '@/features/sources/github-setup'

const tr = (key: string) => i18n.t(`sources:${key}`)
const STATUS: GitHubStatus = { configured: true, missing: [], connected: false, app_id: '4242', slug: 'pitangus-acme', owner: 'acme', name: 'Pitangus Acme', html_url: null,
  source: 'vault', public_url: 'http://127.0.0.1:8766', required_permissions: {}, installation: null, installations: [] }
const ROW = { installation_id: 77, account: 'acme', account_type: 'Organization', repository_selection: 'all', connected: false }

describe('coming back from installing the App on GitHub', () => {
  afterEach(() => window.history.replaceState(null, '', '#/integrations'))

  it('offers the returned installation and connects it with one click', async () => {
    window.history.replaceState(null, '', '#/integrations?installation=77')
    const calls = mockApi(call => {
      if (call.path === '/api/integrations/github' && (call.body as { action: string }).action === 'detect') return { body: { ...STATUS, available_installations: [ROW] } }
      if (call.path === '/api/integrations/github') return { body: { ...STATUS, connected: true, installations: [{ ...ROW, permissions: {}, connected_by: 'admin', connected_at: '2026-10-09T00:00:00Z' }] } }
    })
    const user = userEvent.setup()
    renderWithQueries(<GitHubInstall status={STATUS} canManage onChanged={() => {}} />)
    await waitFor(() => expect(screen.getByRole('status').textContent).toContain('acme'))
    // Offered once: the list below doesn't repeat it.
    expect(screen.getAllByRole('button', { name: tr('github.install.connect') })).toHaveLength(1)
    await user.click(screen.getByRole('button', { name: tr('github.install.connect') }))
    await waitFor(() => expect(calls.some(call => (call.body as { action?: string } | undefined)?.action === 'connect')).toBe(true))
    expect(calls.find(call => (call.body as { action?: string } | undefined)?.action === 'connect')?.body).toEqual({ action: 'connect', installation_id: 77 })
    await waitFor(() => expect(window.location.hash).toBe('#/integrations'))
  })

  it('never looks it up for members', () => {
    window.history.replaceState(null, '', '#/integrations?installation=77')
    const calls = mockApi(() => undefined)
    renderWithQueries(<GitHubInstall status={STATUS} canManage={false} onChanged={() => {}} />)
    expect(calls).toHaveLength(0)
    expect(screen.getByRole('status').textContent).toBe('')
  })
})
