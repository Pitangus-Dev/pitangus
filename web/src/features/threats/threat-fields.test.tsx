import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { DataField, KindField, ProtocolField } from '@/features/threats/threat-fields'
import { AttackMappings } from '@/features/threats/threat-methods'
import type { Catalog, Component, Flow, Model } from '@/features/threats/threat-model-types'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(key, options)
const CATALOG = {
  models: [], assets: [], kinds: { actor: 'Actor', api: 'API', service: 'Service', database: 'Database', custom: 'Custom' },
  protocols: ['https', 'http', 'sql', 'other'], classifications: { public: 'Public', pii: 'Personal data' },
  methods: { methodologies: {}, linddun: {}, tactics: { TA0006: 'Credential Access' }, suggestions: {}, pasta_stages: [],
    techniques: { T1552: { name: 'Unsecured Credentials', name_es: 'Credenciales sin proteger', tactics: ['TA0006'] } },
    attack: { version: '19.2', techniques: { T1552: ['Unsecured Credentials', ['TA0006']], 'T1552.001': ['Credentials In Files', ['TA0006']] }, revoked: { T1562: 'T1685' }, deprecated: {} } },
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

  it('takes any well-formed ATT&CK ID and refuses one that is not', async () => {
    const user = userEvent.setup()
    function Mappings() {
      const [model, setModel] = useState<Model>({ id: 'm', name: 'M', components: [], flows: [], boundaries: [], attack_mappings: [] })
      return <AttackMappings model={model} setModel={setModel} catalog={CATALOG} />
    }
    render(<Mappings />)
    const technique = screen.getByRole('combobox', { name: tr('threats:attack.technique_label') })
    await user.click(technique)
    await user.type(technique, 'X12')
    expect(screen.getByText(tr('threats:attack.technique_format'))).toBeTruthy()
    await user.clear(technique)
    await user.type(technique, 't1552.001{Enter}')
    await user.click(screen.getByRole('button', { name: new RegExp(tr('threats:attack.map')) }))
    const link = screen.getByRole('link', { name: /T1552\.001/ })
    expect(link.getAttribute('href')).toContain('T1552/001')
    // Any ATT&CK technique is named from the bundled catalog; a revoked or unknown ID keeps its ID and says why.
    expect(link.textContent).toContain('Credentials In Files')
    for (const [id, text] of [['T1562', tr('threats:attack.revoked', { replacement: 'T1685' })], ['T9999', tr('threats:attack.not_found', { version: '19.2' })]]) {
      await user.click(technique)
      await user.type(technique, `${id}{Enter}`)
      await user.click(screen.getByRole('button', { name: new RegExp(tr('threats:attack.map')) }))
      expect(screen.getByRole('link', { name: new RegExp(id) }).textContent).toContain(text)
    }
  })
})
