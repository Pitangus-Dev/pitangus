import { describe, expect, it } from 'vitest'
import { useQuery } from '@tanstack/react-query'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { domainsQuery, type DomainTestUser } from '@/shared/api/queries'
import { mockApi, type Call } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { TestUsersPanel } from '@/features/domains/test-users'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const ID = 'a'.repeat(24)
const PASSWORD = 'Correct-Horse-Battery-71'
const SEED = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
const DOMAIN = { id: ID, host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: '', key: 'domain:app.example.com', verified: true, expired: false,
  proof_method: 'dns', headers: [], header_count: 0, runs: 0, open: 0 }

function Panel({ admin }: { admin: boolean }) {
  const domain = useQuery(domainsQuery()).data?.items[0]
  return domain ? <TestUsersPanel domain={domain} admin={admin} /> : null
}

// A server that keeps what it's sent, answering like the API: never a password or a key.
function server(initial: DomainTestUser[] = []) {
  let users = initial
  const calls = mockApi(call => {
    if (call.method === 'GET') return { body: { items: [{ ...DOMAIN, test_users: users, test_user_count: users.length }], total: 1, limit: 20, dast: true } }
    if (call.path === '/api/domains/test-users') {
      const body = call.body as { op: string; id?: string; name: string; method: 'password' | 'password_totp'; username: string; applies_to?: string; login_url?: string; notes?: string }
      if (body.op === 'remove') users = users.filter(user => user.id !== body.id)
      else {
        const user = { id: body.id ?? 'b'.repeat(24), name: body.name, method: body.method, username: body.username, applies_to: body.applies_to || DOMAIN.host,
          login_url: body.login_url || null, notes: body.notes || null, created_at: '2026-10-10T00:00:00Z', last_used_at: null }
        users = [...users.filter(item => item.id !== user.id), user]
      }
      return { body: { domain_id: ID, test_users: users, limit: 10, per_scan: 3 } }
    }
  })
  return calls
}
const sent = (calls: Call[]) => calls.filter(call => call.path === '/api/domains/test-users').map(call => call.body)

describe('test users', () => {
  it('adds one with a username and password, then never shows the password again', async () => {
    const calls = server()
    const user = userEvent.setup()
    renderWithQueries(<Panel admin />)
    expect(await screen.findByText(tr('domains.test_users.empty'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('domains.test_users.add') }))
    const items = (await screen.findAllByRole('menuitem')).map(item => item.textContent)
    expect(items).toEqual([tr('domains.test_users.method.password'), tr('domains.test_users.method.password_totp')])  // no email code, no magic link
    await user.click(screen.getByRole('menuitem', { name: tr('domains.test_users.method.password') }))
    const dialog = await screen.findByRole('dialog', { name: tr('domains.test_users.add_title') })
    await user.type(within(dialog).getByLabelText(tr('domains.test_users.name')), 'Admin user')
    await user.type(within(dialog).getByLabelText(tr('domains.test_users.username')), 'qa@app.example.com')
    const password = within(dialog).getByLabelText(tr('domains.test_users.password'))
    expect(password.getAttribute('autocomplete')).toBe('new-password')
    expect(password.getAttribute('type')).toBe('password')
    expect(within(dialog).queryByLabelText(tr('domains.test_users.totp_secret'))).toBeNull()
    await user.type(password, PASSWORD)
    await user.click(within(dialog).getByText(tr('domains.test_users.advanced')))
    await user.type(within(dialog).getByLabelText(tr('domains.test_users.login_url')), 'https://app.example.com/login')
    await user.click(within(dialog).getByRole('button', { name: tr('domains.test_users.save') }))
    await waitFor(() => expect(sent(calls)).toEqual([{ domain_id: ID, op: 'save', name: 'Admin user', method: 'password', username: 'qa@app.example.com', password: PASSWORD,
      login_url: 'https://app.example.com/login', check_url: '', notes: '', applies_to: 'app.example.com' }]))

    const row = (await screen.findByText('Admin user')).closest('li') as HTMLElement
    expect(within(row).getByText(`qa@app.example.com · ${tr('domains.test_users.method.password')}`)).toBeTruthy()
    expect(await screen.findByText(tr('domains.test_users.saved', { name: 'Admin user' }))).toBeTruthy()
    expect(document.body.textContent).not.toContain(PASSWORD)

    // Editing keeps the saved password unless a new one is typed.
    await user.click(within(row).getByRole('button', { name: tr('domains.test_users.actions_for', { name: 'Admin user' }) }))
    await user.click(await screen.findByRole('menuitem', { name: tr('domains.test_users.edit') }))
    const edit = await screen.findByRole('dialog', { name: tr('domains.test_users.edit_title') })
    expect((within(edit).getByLabelText(tr('domains.test_users.password')) as HTMLInputElement).value).toBe('')
    expect(within(edit).getByText(tr('domains.test_users.keep_saved'))).toBeTruthy()
    await user.click(within(edit).getByRole('button', { name: tr('domains.test_users.save') }))
    await waitFor(() => expect(sent(calls)).toHaveLength(2))
    expect(sent(calls)[1]).not.toHaveProperty('password')
    expect(sent(calls)[1]).toMatchObject({ id: 'b'.repeat(24), op: 'save' })
  })

  it('adds one with an authenticator app, the key typed like a password', async () => {
    const calls = server()
    const user = userEvent.setup()
    renderWithQueries(<Panel admin />)
    await user.click(await screen.findByRole('button', { name: tr('domains.test_users.add') }))
    await user.click(await screen.findByRole('menuitem', { name: tr('domains.test_users.method.password_totp') }))
    const dialog = await screen.findByRole('dialog', { name: tr('domains.test_users.add_title') })
    await user.type(within(dialog).getByLabelText(tr('domains.test_users.name')), 'MFA user')
    await user.type(within(dialog).getByLabelText(tr('domains.test_users.username')), 'mfa')
    await user.type(within(dialog).getByLabelText(tr('domains.test_users.password')), PASSWORD)
    const save = within(dialog).getByRole('button', { name: tr('domains.test_users.save') })
    expect(save.hasAttribute('disabled')).toBe(true)  // the key is required
    const key = within(dialog).getByLabelText(tr('domains.test_users.totp_secret'))
    expect(key.getAttribute('type')).toBe('password')
    await user.type(key, SEED)
    await user.click(save)
    await waitFor(() => expect(sent(calls)[0]).toMatchObject({ method: 'password_totp', totp: { secret: SEED, digits: 6, period: 30, algorithm: 'SHA1' } }))
    expect(document.body.textContent).not.toContain(SEED)
  })

  it('removes one after asking, and members only see how many there are', async () => {
    const saved = { id: 'c'.repeat(24), name: 'Admin user', method: 'password' as const, username: 'qa', applies_to: 'app.example.com', login_url: null, notes: null, last_used_at: '2026-10-09T00:00:00Z' }
    const calls = server([saved])
    const user = userEvent.setup()
    const view = renderWithQueries(<Panel admin />)
    const row = (await screen.findByText('Admin user')).closest('li') as HTMLElement
    await user.click(within(row).getByRole('button', { name: tr('domains.test_users.actions_for', { name: 'Admin user' }) }))
    await user.click(await screen.findByRole('menuitem', { name: tr('domains.test_users.remove') }))
    const question = await screen.findByRole('alertdialog', { name: tr('domains.test_users.remove_title', { name: 'Admin user' }) })
    await user.click(within(question).getByRole('button', { name: tr('domains.test_users.remove') }))
    await waitFor(() => expect(sent(calls)).toEqual([{ domain_id: ID, op: 'remove', id: saved.id }]))
    expect(await screen.findByText(tr('domains.test_users.removed', { name: 'Admin user' }))).toBeTruthy()
    view.unmount()

    mockApi(() => ({ body: { items: [{ ...DOMAIN, test_users: null, test_user_count: 2 }], total: 1, limit: 20, dast: true } }))
    renderWithQueries(<Panel admin={false} />)
    expect(await screen.findByText(tr('domains.test_users.count', { count: 2 }))).toBeTruthy()
    expect(screen.queryByRole('button', { name: tr('domains.test_users.add') })).toBeNull()
  })
})
