import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { DataField, KindField, ProtocolField } from '@/features/threats/threat-fields'
import type { Catalog, Component, Flow } from '@/features/threats/threat-model-types'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(key, options)
const CATALOG = {
  models: [], assets: [], kinds: { actor: 'Actor', api: 'API', service: 'Service', database: 'Database', custom: 'Custom' },
  protocols: ['https', 'http', 'sql', 'other'], classifications: { public: 'Public', pii: 'Personal data' },
  methods: { methodologies: {}, linddun: {}, pasta_stages: [], attack: {} },
  workspace: { protocols: ['mqtt'], kinds: ['Mainframe'], data: ['Telemetry'], techniques: [] },
} as unknown as Catalog

function Flows() {
  const [flow, setFlow] = useState<Flow>({ id: 'f', source: 'a', target: 'b', protocol: 'https', data: [], authenticated: false, encrypted: false })
  const [component, setComponent] = useState<Component>({ id: 'a', name: 'A', kind: 'service', data: [], internet_facing: false, authenticates: false, encrypted_at_rest: false })
  return <>
    <ProtocolField flow={flow} catalog={CATALOG} onChange={change => setFlow({ ...flow, ...change })} />
    <KindField component={component} catalog={CATALOG} onChange={change => setComponent({ ...component, ...change })} />
    <DataField label="data" value={flow.data} catalog={CATALOG} onChange={data => setFlow({ ...flow, data })} />
    <output data-testid="state">{JSON.stringify({ protocol: flow.protocol, data: flow.data, kind: component.kind, custom: component.custom_kind, base: component.custom_base })}</output>
  </>
}

const state = () => JSON.parse(screen.getByTestId('state').textContent ?? '{}') as Record<string, unknown>

describe('fields that take your own values', () => {
  it('suggests ours and the workspace values, and keeps a value Pitangus does not know', async () => {
    const user = userEvent.setup()
    render(<Flows />)
    const protocol = screen.getByRole('combobox', { name: tr('threats:inspector.protocol') })
    await user.click(protocol)
    expect(screen.getByRole('option', { name: /MQTT|mqtt/ })).toBeTruthy()
    await user.type(protocol, 'Wi-Fi <b>6</b>{Enter}')
    expect(state().protocol).toBe('Wi-Fi 6')
    expect(screen.getByText(tr('threats:values.custom_protocol_hint'))).toBeTruthy()
    await user.click(protocol)
    await user.type(protocol, 'lora')
    await user.tab()  // leaving the field keeps what was typed
    expect(state().protocol).toBe('lora')

    const kind = screen.getByRole('combobox', { name: tr('threats:inspector.kind_label') })
    await user.click(kind)
    await user.type(kind, 'Mainframe{Enter}')
    expect(state()).toMatchObject({ kind: 'custom', custom: 'Mainframe', base: 'service' })
    await user.click(kind)
    await user.type(kind, 'api{Enter}')
    expect(state()).toMatchObject({ kind: 'api', custom: '' })

    const data = screen.getByRole('combobox', { name: tr('threats:values.add_data') })
    await user.click(data)
    await user.type(data, 'Health records{Enter}')
    expect(state().data).toEqual(['Health records'])
    expect(screen.getByText(tr('threats:values.custom_data_hint', { values: 'Health records' }))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('threats:values.remove_data', { value: 'Health records' }) }))
    expect(state().data).toEqual([])
  })
})
