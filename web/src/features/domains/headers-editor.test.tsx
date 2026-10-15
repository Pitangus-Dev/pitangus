import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { useQuery } from '@tanstack/react-query'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { domainsQuery } from '@/shared/api/queries'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { HeadersEditor, SessionCheck } from '@/features/domains/headers-editor'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const ID = 'a'.repeat(24)
const SECRET = 'Bearer s3cr3t-value-never-shown'
const DOMAIN = { id: ID, host: 'app.example.com', url: 'https://app.example.com/', kind: 'web', context: '', key: 'domain:app.example.com', verified: true, expired: false,
  proof_method: 'dns', headers: [] as { name: string; last4: string | null; saved_at: string }[], header_count: 0, runs: 0, open: 0 }

function Editor({ admin }: { admin: boolean }) {
  const domain = useQuery(domainsQuery()).data?.items[0]
  const [adding, setAdding] = useState(false)
  return domain ? <><HeadersEditor domain={domain} admin={admin} adding={adding} onAddingChange={setAdding} />{admin && <SessionCheck domain={domain} />}</> : null
}

describe('saved headers', () => {
  it('saves a header, then only ever shows it masked, and removes it after asking', async () => {
    let headers: { name: string; last4: string | null; saved_at: string }[] = []
    const calls = mockApi(call => {
      if (call.method === 'GET') return { body: { items: [{ ...DOMAIN, headers, header_count: headers.length }], total: 1, limit: 20, dast: true } }
      if (call.path === '/api/domains/headers') {
        const body = call.body as { op: string; name: string }
        headers = body.op === 'save' ? [{ name: body.name, last4: 'hown', saved_at: '2026-10-10T00:00:00Z' }] : []
        return { body: { domain_id: ID, headers, limit: 10 } }
      }
    })
    const user = userEvent.setup()
    renderWithQueries(<Editor admin />)
    expect(await screen.findByText(tr('domains.access.empty'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('domains.access.add') }))
    await user.type(screen.getByLabelText(tr('domains.access.name')), 'Authorization')
    const value = screen.getByLabelText(tr('domains.access.value'))
    expect(value.getAttribute('type')).toBe('password')
    expect(value.getAttribute('autocomplete')).toBe('new-password')
    await user.type(value, SECRET)
    await user.click(screen.getByRole('button', { name: tr('domains.access.save') }))

    await waitFor(() => expect(calls.find(call => call.path === '/api/domains/headers')).toEqual({ method: 'POST', path: '/api/domains/headers', action: 'domain-headers',
      body: { domain_id: ID, op: 'save', name: 'Authorization', value: SECRET } }))
    const row = (await screen.findByText('Authorization')).closest('li') as HTMLElement
    expect(within(row).getByText(tr('domains.access.masked'))).toBeTruthy()
    expect(document.body.textContent).not.toContain(SECRET)
    expect(document.body.textContent).not.toContain('hown')
    expect(screen.queryByLabelText(tr('domains.access.value'))).toBeNull()

    await user.click(within(row).getByRole('button', { name: tr('domains.access.actions_for', { name: 'Authorization' }) }))
    await user.click(await screen.findByRole('menuitem', { name: tr('domains.access.replace') }))
    expect((screen.getByLabelText(tr('domains.access.name')) as HTMLInputElement).value).toBe('Authorization')
    expect((screen.getByLabelText(tr('domains.access.value')) as HTMLInputElement).value).toBe('')
    await user.click(screen.getByRole('button', { name: i18n.t('common:actions.cancel') }))

    await user.click(within(row).getByRole('button', { name: tr('domains.access.actions_for', { name: 'Authorization' }) }))
    await user.click(await screen.findByRole('menuitem', { name: tr('domains.access.remove') }))
    const question = await screen.findByRole('alertdialog', { name: tr('domains.access.remove_title', { name: 'Authorization' }) })
    await user.click(within(question).getByRole('button', { name: tr('domains.access.remove') }))
    await waitFor(() => expect(calls.filter(call => call.path === '/api/domains/headers').at(-1)?.body).toEqual({ domain_id: ID, op: 'remove', name: 'Authorization' }))
    expect(await screen.findByText(tr('domains.access.empty'))).toBeTruthy()
  })

  it('saves the session check page with the headers, shows why it was refused, and removes it', async () => {
    let check: string | null = null
    const calls = mockApi(call => {
      if (call.method === 'GET') return { body: { items: [{ ...DOMAIN, headers: [{ name: 'Cookie', last4: null, saved_at: '2026-10-10T00:00:00Z' }], header_count: 1, session_check: check }], total: 1, limit: 20, dast: true } }
      if (call.path === '/api/domains/session-check') {
        const { url } = call.body as { url: string }
        if (url.startsWith('http:')) return { status: 400, body: { error: 'The session check is an HTTPS page' } }
        check = url || null
        return { body: { domain_id: ID, session_check: check } }
      }
    })
    const user = userEvent.setup()
    renderWithQueries(<Editor admin />)
    const field = await screen.findByLabelText(tr('domains.access.check_label'))
    expect(field.getAttribute('aria-describedby')).toBeTruthy()
    const save = screen.getByRole('button', { name: tr('domains.access.check_save') })
    expect((save as HTMLButtonElement).disabled).toBe(true)
    await user.type(field, 'http://app.example.com/account')
    await user.click(save)
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(field.getAttribute('aria-invalid')).toBe('true')
    await user.clear(field)
    await user.type(field, 'https://app.example.com/account')
    await user.click(screen.getByRole('button', { name: tr('domains.access.check_save') }))
    expect(await screen.findByText(tr('domains.access.check_saved'))).toBeTruthy()
    expect(calls.filter(call => call.path === '/api/domains/session-check').at(-1)).toEqual({ method: 'POST', path: '/api/domains/session-check',
      action: 'domain-session-check', body: { domain_id: ID, url: 'https://app.example.com/account' } })
    expect(document.activeElement).not.toBe(document.body)  // the form stays: the focus isn't lost on saving
    await user.click(await screen.findByRole('button', { name: tr('domains.access.check_remove') }))
    expect(await screen.findByText(tr('domains.access.check_removed'))).toBeTruthy()
    const emptied = screen.getByLabelText(tr('domains.access.check_label')) as HTMLInputElement
    expect(emptied.value).toBe('')
    expect(document.activeElement).toBe(emptied)
  })

  it('asks for no session check page while there are no headers', async () => {
    mockApi(() => ({ body: { items: [DOMAIN], total: 1, limit: 20, dast: true } }))
    renderWithQueries(<Editor admin />)
    expect(await screen.findByText(tr('domains.access.empty'))).toBeTruthy()
    expect(screen.queryByLabelText(tr('domains.access.check_label'))).toBeNull()
  })

  it('members only see how many there are', async () => {
    mockApi(() => ({ body: { items: [{ ...DOMAIN, headers: null, header_count: 2 }], total: 1, limit: 20, dast: true } }))
    renderWithQueries(<Editor admin={false} />)
    expect(await screen.findByText(tr('domains.access.count', { count: 2 }))).toBeTruthy()
    expect(screen.queryByRole('button', { name: tr('domains.access.add') })).toBeNull()
  })
})
