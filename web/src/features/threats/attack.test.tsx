import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { basisOf, groupSuggestions, suggestedFor, type AttackCatalog } from '@/features/threats/attack-catalog'
import { AddComponentMenu } from '@/features/threats/threat-canvas'
import { AttackMappings } from '@/features/threats/threat-methods'
import type { Catalog, Component, Model } from '@/features/threats/threat-model-types'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`threats:${key}`, options)
const HOSTS = ['Windows', 'macOS', 'Linux']
// A slice of ATT&CK v19.2 as the server sends it (names, tactics and platforms as MITRE publishes them), with the
// server's own suggestion table.
const ATTACK: AttackCatalog = {
  version: '19.2', source: 'https://github.com/mitre-attack/attack-stix-data',
  counts: { total: 697, techniques: 222, subtechniques: 475, revoked: 149, deprecated: 12 },
  tactics: { TA0001: 'Initial Access', TA0002: 'Execution', TA0003: 'Persistence', TA0006: 'Credential Access', TA0009: 'Collection', TA0010: 'Exfiltration', TA0040: 'Impact' },
  platforms: ['Windows', 'macOS', 'Linux', 'Identity Provider', 'SaaS', 'IaaS', 'Containers'],
  techniques: {
    T1059: ['Command and Scripting Interpreter', ['TA0002'], ['Windows', 'macOS', 'Linux', 'IaaS', 'Containers']],
    'T1059.004': ['Unix Shell', ['TA0002'], ['macOS', 'Linux']],
    T1190: ['Exploit Public-Facing Application', ['TA0001'], ['Windows', 'macOS', 'Linux', 'IaaS', 'Containers']],
    T1530: ['Data from Cloud Storage', ['TA0009'], ['Office Suite', 'SaaS', 'IaaS']],
    T1552: ['Unsecured Credentials', ['TA0006'], ['Windows', 'macOS', 'Linux', 'Identity Provider', 'SaaS', 'IaaS', 'Containers']],
    'T1552.001': ['Credentials In Files', ['TA0006'], ['Windows', 'macOS', 'Linux', 'IaaS', 'Containers']],
    T1556: ['Modify Authentication Process', ['TA0003', 'TA0006'], ['Windows', 'macOS', 'Linux', 'Identity Provider', 'SaaS', 'IaaS']],
    T1610: ['Deploy Container', ['TA0002'], ['Containers']],
  },
  revoked: { T1562: 'T1685' }, deprecated: {},
  translations: { es: { tactics: { TA0002: 'Ejecución', TA0006: 'Acceso a credenciales' }, techniques: { T1059: 'Intérprete de comandos y scripts', T1552: 'Credenciales sin proteger' } } },
  suggestions: {
    kinds: { api: { platforms: HOSTS, tactics: ['TA0002', 'TA0006', 'TA0040'] }, service: { platforms: HOSTS, tactics: ['TA0002', 'TA0006', 'TA0040'] },
             storage: { platforms: ['IaaS'], tactics: ['TA0009', 'TA0010', 'TA0040'] }, identity: { platforms: ['Identity Provider'], tactics: ['TA0001', 'TA0003', 'TA0006'] } },
    hosts: HOSTS, internet_tactic: 'TA0001', container_platform: 'Containers', container_terms: ['docker', 'kubernetes', 'k8s', 'cloud run'],
  },
}
const CATALOG = { models: [], assets: [], kinds: {}, protocols: [], classifications: {}, workspace: { techniques: [] },
  methods: { methodologies: {}, linddun: {}, pasta_stages: [], attack: ATTACK } } as unknown as Catalog
const part = (id: string, name: string, kind: Component['kind'], extra: Partial<Component> = {}): Component =>
  ({ id, name, kind, data: [], internet_facing: false, authenticates: false, encrypted_at_rest: false, ...extra })
const API = part('api', 'Orders API', 'api', { internet_facing: true })
const WORKER = part('worker', 'Worker', 'service', { technology: 'Python on Kubernetes' })
const BUCKET = part('bucket', 'Invoices', 'storage')
const USER = part('user', 'Customer', 'actor')
const CAMERA = part('camera', 'IP camera', 'custom', { custom_kind: 'IP camera', custom_base: 'service' })

function Mappings({ components = [API, WORKER, BUCKET, USER, CAMERA] }: { components?: Component[] }) {
  const [model, setModel] = useState<Model>({ id: 'm', name: 'M', components, flows: [], boundaries: [], attack_mappings: [] })
  return <><AttackMappings model={model} setModel={setModel} catalog={CATALOG} />
    <output data-testid="rows">{JSON.stringify((model.attack_mappings ?? []).map(row => `${row.technique}@${row.element}`))}</output></>
}
const rows = () => JSON.parse(screen.getByTestId('rows').textContent ?? '[]') as string[]

describe('ATT&CK suggestions from MITRE platforms', () => {
  it('applies the server table: platforms, tactics, exposure and containers', () => {
    expect(basisOf(ATTACK, API)).toEqual({ platforms: HOSTS, tactics: ['TA0001', 'TA0002', 'TA0006', 'TA0040'] })
    expect(suggestedFor(ATTACK, API)).toEqual(['T1059', 'T1190', 'T1552', 'T1556'])  // techniques only, never sub-techniques
    expect(suggestedFor(ATTACK, { ...API, internet_facing: false })).not.toContain('T1190')
    expect(basisOf(ATTACK, WORKER)?.platforms).toEqual([...HOSTS, 'Containers'])
    expect(suggestedFor(ATTACK, WORKER)).toContain('T1610')
    expect(suggestedFor(ATTACK, BUCKET)).toEqual(['T1530'])
    // A person and a type of your own have no ATT&CK platform: no suggestions, whatever the base role.
    expect(basisOf(ATTACK, USER)).toBeNull()
    expect(suggestedFor(ATTACK, CAMERA)).toEqual([])
  })

  it('groups by technique, in kill-chain order, without what is already mapped', () => {
    const groups = groupSuggestions(ATTACK, [API, WORKER, BUCKET], (id, element) => id === 'T1552' && element === 'worker')
    expect(groups.map(group => [group.id, group.tactic, group.components.map(item => item.id)])).toEqual([
      ['T1190', 'TA0001', ['api']], ['T1059', 'TA0002', ['api', 'worker']], ['T1610', 'TA0002', ['worker']],
      ['T1552', 'TA0006', ['api']], ['T1556', 'TA0006', ['api', 'worker']], ['T1530', 'TA0009', ['bucket']]])
  })

  it('shows one row per technique, adds it to one component or to all, and says who gets none', async () => {
    const user = userEvent.setup()
    render(<Mappings />)
    expect(screen.getByText(tr('attack.suggestions_hint'))).toBeTruthy()
    expect(screen.getByText(tr('attack.suggestions_silent', { names: 'Customer, IP camera' }))).toBeTruthy()
    const list = screen.getByRole('group', { name: tr('attack.suggestions_list') })
    expect(within(list).getAllByText('Command and Scripting Interpreter')).toHaveLength(1)
    await user.click(within(list).getByRole('button', { name: tr('attack.add_all_label', { id: 'T1059', names: 'Orders API, Worker' }) }))
    expect(rows()).toEqual(['T1059@api', 'T1059@worker'])
    await user.click(screen.getByRole('button', { name: tr('attack.add_to', { id: 'T1530', name: 'Invoices' }) }))
    expect(rows()).toEqual(['T1059@api', 'T1059@worker', 'T1530@bucket'])
    expect(screen.queryByRole('button', { name: tr('attack.add_to', { id: 'T1059', name: 'Worker' }) })).toBeNull()  // mapped: gone
    // A mapped technique reads by MITRE's name, with its tactics.
    expect(screen.getByRole('link', { name: /T1530/ }).textContent).toContain('Data from Cloud Storage')
  })
})

describe('ATT&CK picker', () => {
  it('browses the whole catalog by tactic, searches, and suggests for the chosen component first', async () => {
    const user = userEvent.setup()
    render(<Mappings />)
    await user.click(screen.getByRole('button', { name: tr('attack.map_technique') }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText(tr('attack.picker.source', { version: '19.2', total: 697, techniques: 222, subtechniques: 475 }))).toBeTruthy()
    // By tactic: each technique once, under its first tactic; a tactic chip shows every technique that has it.
    expect(within(dialog).getByRole('heading', { name: /Initial Access/ })).toBeTruthy()
    await user.click(within(dialog).getByRole('button', { name: 'Persistence' }))
    expect(within(dialog).getByText('Modify Authentication Process')).toBeTruthy()
    expect(within(dialog).queryByText('Deploy Container')).toBeNull()
    await user.click(within(dialog).getByRole('button', { name: tr('attack.picker.all_tactics') }))
    // Sub-techniques open under their technique, and a search finds them by name.
    await user.click(within(dialog).getAllByRole('button', { name: tr('attack.picker.subtechniques', { count: 1 }) })[0])
    expect(within(dialog).getByText('Unix Shell')).toBeTruthy()
    const search = within(dialog).getByRole('searchbox', { name: tr('attack.picker.search') })
    await user.type(search, 'credentials in')
    expect(within(dialog).getByText('Credentials In Files')).toBeTruthy()
    expect(within(dialog).queryByText('Deploy Container')).toBeNull()
    await user.clear(search)
    await user.type(search, 'collection')  // by tactic
    expect(within(dialog).getByText('Data from Cloud Storage')).toBeTruthy()
    await user.clear(search)

    await user.click(within(dialog).getByRole('combobox', { name: tr('attack.picker.element') }))
    await user.click(await screen.findByRole('option', { name: 'Worker' }))
    const suggested = within(dialog).getByRole('region', { name: tr('attack.picker.suggested_for', { name: 'Worker' }) })
    expect(within(suggested).getByText(tr('attack.picker.basis', { platforms: 'Windows, macOS, Linux, Containers', tactics: 'Execution, Credential Access, Impact' }))).toBeTruthy()
    await user.click(within(suggested).getByRole('button', { name: tr('attack.picker.map_to', { id: 'T1610', name: 'Worker' }) }))
    expect(rows()).toEqual(['T1610@worker'])
    expect(within(suggested).getAllByText(tr('attack.picker.mapped')).length).toBeGreaterThan(0)

    await user.click(within(dialog).getByRole('combobox', { name: tr('attack.picker.element') }))
    await user.click(await screen.findByRole('option', { name: 'Customer' }))
    expect(within(dialog).getByText(tr('attack.picker.no_platform_actor'))).toBeTruthy()
  })

  it('takes any well-formed ATT&CK ID and says when one is revoked or unknown', async () => {
    const user = userEvent.setup()
    render(<Mappings components={[]} />)
    await user.click(screen.getByRole('button', { name: tr('attack.map_technique') }))
    const dialog = screen.getByRole('dialog')
    const search = within(dialog).getByRole('searchbox', { name: tr('attack.picker.search') })
    await user.type(search, 'T12')
    expect(within(dialog).getByText(tr('attack.technique_format'))).toBeTruthy()
    for (const id of ['T9999', 'T1562']) {
      await user.clear(search)
      await user.type(search, id.toLowerCase())
      await user.click(within(dialog).getByRole('button', { name: tr('attack.picker.map_to', { id, name: tr('manual.whole_system') }) }))
    }
    await user.click(within(dialog).getByRole('button', { name: tr('attack.picker.done') }))
    expect(rows()).toEqual(['T9999@', 'T1562@'])
    expect(screen.getByRole('link', { name: /T9999/ }).textContent).toContain(tr('attack.not_found', { version: '19.2' }))
    expect(screen.getByRole('link', { name: /T1562/ }).textContent).toContain(tr('attack.revoked', { replacement: 'T1685' }))
  })
})

describe('add component menu', () => {
  it('sizes to its longest item and stays inside the window', async () => {
    const user = userEvent.setup()
    const added: string[] = []
    render(<AddComponentMenu kinds={{ actor: 'User or external actor', api: 'API / backend' } as Record<Component['kind'], string>} onAdd={kind => added.push(kind)} />)
    await user.click(screen.getByRole('combobox', { name: tr('canvas.add_component') }))
    const option = await screen.findByRole('option', { name: 'User or external actor' })
    const popup = option.closest('[data-slot="select-content"]') as HTMLElement
    expect(popup.classList.contains('w-max')).toBe(true)
    expect(popup.classList.contains('max-w-(--available-width)')).toBe(true)
    expect(popup.classList.contains('w-(--anchor-width)')).toBe(false)  // the old fixed width that clipped the items
    await user.click(option)
    expect(added).toEqual(['actor'])
  })
})
