import { beforeAll, describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import type { SessionUser } from '@/features/auth/session'
import type { Catalog, Model, View } from '@/features/threats/threat-model-types'
import { ThreatModels } from '@/pages/ThreatModels'
import { mockApi } from '@/shared/test/api'
import { mockReactFlowLayout } from '@/shared/test/react-flow'
import { renderWithQueries } from '@/shared/test/render'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`threats:${key}`, options)
const USER = { id: 'u', username: 'ana', display_name: 'Ana', role: 'member', totp_enabled: true, last_login_at: null } as SessionUser
const service = (id: string, x: number) => ({ id, name: id.toUpperCase(), kind: 'service' as const, data: [], internet_facing: false, authenticates: false, encrypted_at_rest: false, position: { x, y: 80 } })
const MODEL: Model = { id: 'm', name: 'Shop', methodology: 'stride', boundaries: [], components: [service('web', 40), service('api', 440)],
  flows: [{ id: 'web-api', source: 'web', target: 'api', protocol: 'https', data: [], authenticated: true, encrypted: true }] }
const VIEW: View = { model: MODEL, threats: [], summary: { total: 0, by_status: {}, by_stride: {}, by_severity: {} } }
const CATALOG = { models: [{ id: 'm', name: 'Shop', components: 2, flows: 1 }], assets: [], kinds: { service: 'Service' }, protocols: ['https'], classifications: {},
  workspace: {}, methods: { methodologies: {}, linddun: {}, pasta_stages: [], attack: {} } } as unknown as Catalog

beforeAll(mockReactFlowLayout)

describe('threat model editor', () => {
  it('saves where the team moved a flow label', async () => {
    const calls = mockApi(call => call.path === '/api/threat-models' && call.method === 'GET' ? { body: CATALOG }
      : call.path === '/api/threat-models/m' ? { body: VIEW }
      : call.method === 'POST' ? { body: { ...VIEW, model: { ...MODEL, ...(call.body as { model: Model }).model } } } : undefined)
    const user = userEvent.setup()
    renderWithQueries(<ThreatModels user={USER} onOpenRun={() => {}} />)
    await user.click(await screen.findByRole('button', { name: /Shop/ }))
    await user.click(await screen.findByRole('button', { name: tr('tabs.diagram') }))
    const label = await screen.findByRole('button', { name: tr('canvas.aria.flow_label', { label: '1 · HTTPS' }) })
    label.focus()
    await user.keyboard('{ArrowUp}')
    await user.click(screen.getByRole('button', { name: tr('editor.save') }))
    await waitFor(() => expect(calls.some(call => call.action === 'save-threat-model')).toBe(true))
    const saved = calls.find(call => call.action === 'save-threat-model')!.body as { model: Model }
    expect(saved.model.flows[0].label_offset).toEqual({ x: 0, y: -8 })
  })
})
