import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Call, type Reply } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import type { Response } from '@/shared/api/client'
import { EngineSwitches } from '@/features/engines/engine-switches'

type View = Response<'/api/engines'>
type Row = View['engines'][number]
const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`engines:${key}`, options)

const row = (key: string, overrides: Partial<Row> = {}): Row => ({
  key, name: { opengrep: 'Opengrep', betterleaks: 'Betterleaks', trivy: 'Trivy', checkov: 'Checkov', dast: 'ZAP' }[key] ?? key, version: '1.0.0',
  group: key === 'betterleaks' ? 'secrets' : key === 'checkov' ? 'infrastructure' : key === 'dast' ? 'web' : 'code',
  covers: { opengrep: ['sast'], betterleaks: ['secrets'], trivy: ['dependencies', 'secrets', 'iac', 'images'], checkov: ['iac', 'pipelines'], dast: ['dast'] }[key] ?? [],
  requires: null, enabled: true, default: true, locked: false, source: 'default', setting: `PITANGUS_${key.toUpperCase()}_ENABLED`,
  changed_by: null, changed_at: null, image: 'ready', image_problem: null, ...overrides,
})
const VIEW: View = {
  engines: [row('opengrep'), row('trivy'), row('betterleaks'), row('checkov', { enabled: false, default: false, image: 'missing' }),
    row('dast', { enabled: false, default: false, locked: true, source: 'server', setting: 'PITANGUS_DAST_ENABLED' })],
  uncovered: [], images_checked_at: '2026-10-15T10:00:00Z', history: [],
}

function server(view: View = VIEW, overrides: (call: Call) => Reply | undefined = () => undefined) {
  return mockApi(call => overrides(call) ?? (call.path === '/api/engines' && call.method === 'GET' ? { body: view } : undefined))
}
const switchOf = (name: string) => screen.getByRole('switch', { name: new RegExp(`^${name}`) })
const item = (name: string) => switchOf(name).closest('li') as HTMLElement

describe('EngineSwitches', () => {
  it('groups the engines by what they cover, each with what it adds and where its state comes from', async () => {
    server()
    renderWithQueries(<EngineSwitches />)
    await screen.findByRole('switch', { name: /^Opengrep/ })
    for (const group of ['code', 'secrets', 'infrastructure', 'images', 'web'] as const)
      expect(screen.getByRole('heading', { level: 2, name: tr(`groups.${group}.title`) })).toBeTruthy()
    expect(within(item('Opengrep')).getByText(tr('rows.opengrep.adds'))).toBeTruthy()
    expect(within(item('Opengrep')).getByText(tr('status.default_on'))).toBeTruthy()
    expect(switchOf('Opengrep').getAttribute('aria-checked')).toBe('true')
    expect(switchOf('Checkov').getAttribute('aria-checked')).toBe('false')
  })

  it('shows a switch the server pins as locked, naming its variable', async () => {
    server()
    renderWithQueries(<EngineSwitches />)
    const dast = await screen.findByRole('switch', { name: new RegExp(`^${tr('rows.dast.title')}`) })
    expect((dast as HTMLButtonElement).disabled).toBe(true)
    expect(within(dast.closest('li') as HTMLElement).getByText(tr('status.locked', { setting: 'PITANGUS_DAST_ENABLED' }))).toBeTruthy()
  })

  it('asks before turning off a core engine, saying what goes unchecked and that nothing is marked fixed', async () => {
    const calls = server(VIEW, call => call.method === 'POST' && call.path === '/api/engines'
      ? { body: { ...VIEW, engines: VIEW.engines.map(item => item.key === 'opengrep' ? { ...item, enabled: false, source: 'workspace' as const, changed_by: 'ana', changed_at: '2026-10-15T11:00:00Z' } : item) } }
      : undefined)
    const user = userEvent.setup()
    renderWithQueries(<EngineSwitches />)
    await user.click(await screen.findByRole('switch', { name: /^Opengrep/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText(tr('confirm.off_core', { name: 'Opengrep', covers: tr('rows.opengrep.covers') }))).toBeTruthy()
    // Opengrep is the only SAST engine: the dialog says the scans will report it unchecked.
    expect(within(dialog).getByText(tr('confirm.off_last', { what: tr('capability.sast') }))).toBeTruthy()
    await user.click(within(dialog).getByRole('button', { name: tr('confirm.off') }))
    await waitFor(() => expect(calls.some(call => call.method === 'POST')).toBe(true))
    const sent = calls.find(call => call.method === 'POST')
    expect(sent).toMatchObject({ path: '/api/engines', action: 'engine-switch', body: { engine: 'opengrep', enabled: false } })
    await waitFor(() => expect(switchOf('Opengrep').getAttribute('aria-checked')).toBe('false'))
    expect(screen.getByText(tr('saved_off', { name: 'Opengrep' }))).toBeTruthy()
  })

  it('sends nothing when the confirmation is cancelled', async () => {
    const calls = server()
    const user = userEvent.setup()
    renderWithQueries(<EngineSwitches />)
    await user.click(await screen.findByRole('switch', { name: /^Trivy/ }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: i18n.t('common:actions.cancel') }))
    expect(calls.filter(call => call.method === 'POST')).toHaveLength(0)
  })

  it('shows each image status and prepares a missing one', async () => {
    const calls = server(VIEW, call => call.method === 'POST' && call.path === '/api/engines/prepare'
      ? { body: { ...VIEW, engines: VIEW.engines.map(item => item.key === 'checkov' ? { ...item, image: 'preparing' as const } : item) } }
      : undefined)
    const user = userEvent.setup()
    renderWithQueries(<EngineSwitches />)
    await screen.findByRole('switch', { name: /^Checkov/ })
    expect(within(item('Opengrep')).getByText(tr('image.ready'))).toBeTruthy()
    expect(within(item('Checkov')).getByText(tr('image.missing'))).toBeTruthy()
    expect(within(item('Opengrep')).queryByRole('button', { name: tr('image.prepare_label', { name: 'Opengrep' }) })).toBeNull()
    await user.click(within(item('Checkov')).getByRole('button', { name: tr('image.prepare_label', { name: 'Checkov' }) }))
    await waitFor(() => expect(within(item('Checkov')).getByText(tr('image.preparing'))).toBeTruthy())
    expect(calls.find(call => call.method === 'POST')).toMatchObject({ path: '/api/engines/prepare', action: 'prepare-engine', body: { engine: 'checkov' } })
  })

  it('warns when a kind of check is left with no engine on', async () => {
    server({ ...VIEW, uncovered: ['secrets'] })
    renderWithQueries(<EngineSwitches />)
    expect(await screen.findByText(tr('uncovered', { what: tr('capability.secrets') }))).toBeTruthy()
  })
})
