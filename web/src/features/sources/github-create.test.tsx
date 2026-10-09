import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { GitHubAppCreate } from '@/features/sources/github-create'

const tr = (key: string) => i18n.t(`sources:${key}`)

describe('creating the GitHub App from the panel', () => {
  afterEach(() => vi.restoreAllMocks())

  it('asks the server for the manifest and posts it to GitHub', async () => {
    const submitted: { action: string; method: string; manifest: string | null }[] = []
    vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(function (this: HTMLFormElement) {
      submitted.push({ action: this.action, method: this.method, manifest: (this.elements.namedItem('manifest') as HTMLInputElement | null)?.value ?? null })
    })
    const calls = mockApi(call => {
      if (call.path === '/api/integrations/github/manifest') return { body: { url: 'https://github.com/organizations/acme/settings/apps/new?state=s', manifest: '{"name":"Pitangus acme"}' } }
    })
    const user = userEvent.setup()
    renderWithQueries(<GitHubAppCreate canManage />)
    await user.type(screen.getByLabelText(tr('github.create.organization')), 'ac me!')
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: tr('github.create.submit') }))

    await waitFor(() => expect(submitted).toHaveLength(1))
    expect(calls.find(call => call.method === 'POST')).toEqual({ method: 'POST', path: '/api/integrations/github/manifest', action: 'create-github-app',
      body: { name: 'Pitangus acme', organization: 'acme', any_account: true } })
    expect(submitted[0]).toEqual({ action: 'https://github.com/organizations/acme/settings/apps/new?state=s', method: 'post', manifest: '{"name":"Pitangus acme"}' })
  })

  it('is read-only for members', () => {
    renderWithQueries(<GitHubAppCreate canManage={false} />)
    expect((screen.getByRole('button', { name: tr('github.create.submit') }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(tr('github.form.admin_only'))).toBeTruthy()
  })
})
