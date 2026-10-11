import { afterEach, describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call, type Reply } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import type { SessionUser } from '@/features/auth/session'
import type { GitHubStatus } from '@/features/sources/github-setup'
import { Integrations } from '@/pages/Integrations'

const src = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`integrations:${key}`, options)
const ADMIN: SessionUser = { id: 'u1', username: 'admin', display_name: 'Admin', role: 'admin', totp_enabled: false, last_login_at: null }
const MEMBER: SessionUser = { ...ADMIN, id: 'u2', username: 'member', role: 'member' }
const GITHUB: GitHubStatus = { configured: true, missing: [], connected: true, app_id: '4242', slug: 'pitangus-acme', owner: 'acme', name: 'Pitangus Acme', html_url: null,
  source: 'vault', public_url: 'http://127.0.0.1:8766', required_permissions: {}, installation: null,
  installations: [{ installation_id: 77, account: 'acme', account_type: 'Organization', repository_selection: 'all', permissions: {}, connected_by: 'admin', connected_at: '2026-10-09T00:00:00Z' }] }
const NOTIFICATIONS = { channels: [], kinds: { slack: 'Slack', teams: 'Microsoft Teams', webhook: 'Webhook' }, events: { findings: 'New findings', batch: 'Finished batches' }, thresholds: ['critical', 'high', 'medium'], links: true }

function server(overrides: (call: Call) => Reply | undefined = () => undefined) {
  return mockApi(call => overrides(call) ?? (
    call.path === '/api/integrations/github' ? { body: GITHUB }
    : call.path.startsWith('/api/sources') ? { body: { sources: [], providers: { github: { configured: true, origin: 'github_app' }, gitlab: { configured: false, origin: null } }, total: 0, page: 1, per_page: 1 } }
    : call.path === '/api/registries' ? { body: { registries: [], allow_private: false } }
    : call.path === '/api/notifications' ? { body: NOTIFICATIONS }
    : call.path === '/api/integrations/jira' ? { body: { configured: false } }
    : call.path === '/api/providers' ? { body: [{ id: 'openai', configured: true, env: 'OPENAI_API_KEY', owner: 'user', last4: '9xyz', saved_at: null }] }
    : undefined))
}
const row = (name: string) => screen.getByRole('heading', { level: 3, name }).closest('li') as HTMLElement

describe('Integrations', () => {
  afterEach(() => window.history.replaceState(null, '', '#/integrations'))

  it('reads as plain sections of rows, each with one status line', async () => {
    server()
    renderWithQueries(<Integrations user={ADMIN} />)
    for (const title of [src('providers.title'), src('registries.title'), tr('notifications.title'), tr('page.issues_title'), tr('page.ai.title')])
      expect(screen.getByRole('heading', { level: 2, name: title })).toBeTruthy()
    const github = await waitFor(() => within(row('GitHub')).getByText(src('providers.row.connected', { count: 1 })))
    // Connected reads as success, not as the brand color.
    expect(github.className).toContain('text-success')
    expect(within(row('Jira Cloud')).getByText(tr('jira.status.not_configured'))).toBeTruthy()
    expect(within(row('GitLab')).getByText(src('providers.row.soon'))).toBeTruthy()
  })

  it('folds each configuration under its row until asked for', async () => {
    server()
    const user = userEvent.setup()
    renderWithQueries(<Integrations user={ADMIN} />)
    const manage = await screen.findByRole('button', { name: src('providers.row.manage') })
    expect(manage.getAttribute('aria-expanded')).toBe('false')
    expect(screen.queryByRole('button', { name: src('providers.disconnect_account') })).toBeNull()
    await user.click(manage)
    expect(manage.getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByRole('button', { name: src('providers.disconnect_account') })).toBeTruthy()
  })

  it('opens the GitHub panel by itself when coming back from installing the App', async () => {
    window.history.replaceState(null, '', '#/integrations?installation=77')
    server(call => call.path === '/api/integrations/github' && call.method === 'POST' ? { body: { ...GITHUB, available_installations: [] } } : undefined)
    renderWithQueries(<Integrations user={ADMIN} />)
    expect((await screen.findByRole('button', { name: src('providers.row.manage') })).getAttribute('aria-expanded')).toBe('true')
  })

  it('adds a registry from the inline form and folds it again', async () => {
    const calls = server(call => call.path === '/api/registries' && call.method === 'POST'
      ? { body: { registries: [{ registry: 'ghcr.io', username: 'octo', last4: 'abcd', saved_at: null, saved_by: null }] } } : undefined)
    const user = userEvent.setup()
    renderWithQueries(<Integrations user={ADMIN} />)
    await screen.findByText(src('registries.row.none'))
    const add = screen.getByRole('button', { name: src('registries.add') })
    await user.click(add)
    await user.type(screen.getByLabelText(src('registries.host')), 'ghcr.io')
    await user.type(screen.getByLabelText(src('registries.username')), 'octo')
    await user.type(screen.getByLabelText(src('registries.token')), 'secret-token')
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.save') }))
    await waitFor(() => expect(within(row('ghcr.io')).getByText(src('registries.row.saved'))).toBeTruthy())
    expect(calls.find(call => call.path === '/api/registries' && call.method === 'POST')?.body).toEqual({ action: 'save', registry: 'ghcr.io', username: 'octo', token: 'secret-token' })
    expect(add.getAttribute('aria-expanded')).toBe('false')
  })

  it('keeps the notification form folded even with no channels', async () => {
    server()
    const user = userEvent.setup()
    renderWithQueries(<Integrations user={ADMIN} />)
    await screen.findByText(tr('notifications.row.none'))
    const form = screen.getByLabelText(tr('notifications.url')).closest('form') as HTMLFormElement
    expect(form.hidden).toBe(true)
    await user.click(screen.getByRole('button', { name: tr('notifications.add') }))
    expect(form.hidden).toBe(false)
  })

  it('lists an old AI key so an administrator can remove it', async () => {
    const calls = server(call => call.path === '/api/providers/keys' ? { body: { providers: [] } } : undefined)
    const user = userEvent.setup()
    renderWithQueries(<Integrations user={ADMIN} />)
    await user.click(await within(row('OpenAI')).findByRole('button', { name: tr('page.ai.remove_key') }))
    await waitFor(() => expect(calls.find(call => call.path === '/api/providers/keys')?.body).toEqual({ provider: 'openai', action: 'remove' }))
    await waitFor(() => expect(within(row('OpenAI')).queryByRole('button')).toBeNull())
  })

  it('says a connection could not be checked instead of loading forever or claiming it is not set up', async () => {
    server(call => call.path === '/api/integrations/github' || call.path === '/api/integrations/jira' ? { status: 500, body: { detail: 'boom' } } : undefined)
    renderWithQueries(<Integrations user={ADMIN} />)
    expect((await within(row('GitHub')).findByText(src('providers.row.unavailable'))).className).toContain('text-danger')
    expect((await within(row('Jira Cloud')).findByText(tr('jira.status.unknown'))).className).toContain('text-danger')
    expect(within(row('Jira Cloud')).queryByText(tr('jira.status.not_configured'))).toBeNull()
    expect(within(row('GitHub')).queryByRole('status')).toBeNull()
  })

  it('shows members the state without notifications or setup forms', async () => {
    server()
    renderWithQueries(<Integrations user={MEMBER} />)
    expect(screen.getByText(tr('page.read_only'))).toBeTruthy()
    expect(screen.queryByRole('heading', { level: 2, name: tr('notifications.title') })).toBeNull()
    expect(await within(row('Jira Cloud')).findByText(tr('jira.admin_only'))).toBeTruthy()
    expect(within(row('Jira Cloud')).queryByRole('button')).toBeNull()
    expect(screen.queryByRole('button', { name: src('registries.add') })).toBeNull()
  })
})
