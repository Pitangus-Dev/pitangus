import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { LinkImagesDialog } from '@/features/sources/link-images-dialog'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`sources:${key}`, options)
const REPO = { key: 'github#1', name: 'org/api' }
const image = (name: string, built: { repository: string; name: string } | null, analyzed = true) => ({ key: `image:${name}`, name, reference: `${name}:1`,
  analyzed, last_scan: null, last_complete: null, built_from: built && { ...built, revision: null, how: 'manual' } })
const page = (items: unknown[]) => ({ items, total: items.length, limit: 50, offset: 0, counts: { all: items.length, unlinked: 0, label: 0, manual: 0 }, repositories: {} })

describe('linking images from a repository', () => {
  it('lists every image with where it is built from now, and links the chosen ones in one go', async () => {
    const items = [image('ghcr.io/org/api', null, false), image('ghcr.io/org/worker', { repository: 'github#2', name: 'org/old' }), image('ghcr.io/org/web', { repository: REPO.key, name: REPO.name })]
    const calls = mockApi(call => call.path.startsWith('/api/images') ? { body: page(items) } : call.path === '/api/evidence/image-link' ? { body: { built_from: null } } : undefined)
    const linked = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<LinkImagesDialog repository={REPO} onClose={() => {}} onLinked={linked} onAddImage={() => {}} />)
    const dialog = await screen.findByRole('dialog')
    const row = (name: string) => within(dialog).getByRole('checkbox', { name: new RegExp(name.replaceAll('.', '\\.')) })
    await within(dialog).findByText('ghcr.io/org/web')
    // The one already built from this repository is shown as such and can't be chosen again.
    expect((row('ghcr.io/org/web') as HTMLInputElement).disabled).toBe(true)
    expect(within(dialog).getByText(tr('images.link_dialog.already'))).toBeTruthy()
    expect(within(dialog).getByText(tr('images.currently', { name: 'org/old' }))).toBeTruthy()
    const submit = within(dialog).getByRole('button', { name: tr('images.link_dialog.submit', { count: 0 }) })
    expect((submit as HTMLButtonElement).disabled).toBe(true)
    await user.click(row('ghcr.io/org/api'))
    await user.click(row('ghcr.io/org/worker'))
    await user.click(within(dialog).getByRole('button', { name: tr('images.link_dialog.submit', { count: 2 }) }))
    await waitFor(() => expect(linked).toHaveBeenCalledWith(2))
    expect(calls.filter(call => call.method === 'POST').map(call => call.body)).toEqual([
      { image: 'image:ghcr.io/org/api', repository: 'github#1' }, { image: 'image:ghcr.io/org/worker', repository: 'github#1' }])
  })

  it('keeps what failed chosen, with its reason', async () => {
    mockApi(call => call.path.startsWith('/api/images') ? { body: page([image('ghcr.io/org/api', null)]) }
      : call.path === '/api/evidence/image-link' ? { status: 400, body: { error: 'That image is gone' } } : undefined)
    const linked = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<LinkImagesDialog repository={REPO} onClose={() => {}} onLinked={linked} onAddImage={() => {}} />)
    const dialog = await screen.findByRole('dialog')
    await user.click(await within(dialog).findByRole('checkbox', { name: /ghcr\.io\/org\/api/ }))
    await user.click(within(dialog).getByRole('button', { name: tr('images.link_dialog.submit', { count: 1 }) }))
    expect(await within(dialog).findByText(tr('images.link_dialog.failed', { image: 'ghcr.io/org/api', error: 'That image is gone' }))).toBeTruthy()
    expect(linked).not.toHaveBeenCalled()
    expect((within(dialog).getByRole('checkbox', { name: /ghcr\.io\/org\/api/ }) as HTMLInputElement).checked).toBe(true)
  })

  it('without images, offers adding one by its reference', async () => {
    mockApi(call => call.path.startsWith('/api/images') ? { body: page([]) } : undefined)
    const add = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<LinkImagesDialog repository={REPO} onClose={() => {}} onLinked={() => {}} onAddImage={add} />)
    await user.click(await screen.findByRole('button', { name: tr('images.add.open') }))
    expect(add).toHaveBeenCalledOnce()
  })
})
