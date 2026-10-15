import { describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi, type Reply } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { ThreatJsonImporter } from '@/features/threats/threat-json-importer'
import { locate, spanOf } from '@/features/threats/json-locate'
import schema from '@/examples/threat-models/schema.json'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`threats:${key}`, options)
const PREVIEW = { name: 'Shop', methodology: 'custom', components: 3, flows: 2, boundaries: 1, repository_refs: 0, manual_threats: 0, attack_trees: 0,
  attack_mappings: 2, pasta_stages: 0, relayout: false }
const DOCUMENT = {
  format: 'pitangus-threat-model', version: 1,
  model: { name: 'Shop', methodology: 'attack', components: [{ id: 'web', name: 'Web', kind: 'web_app' }, { id: 'api', name: 'API', kind: 'api' }],
    flows: [{ id: 'calls', source: 'web', target: 'api', protocol: 'wifi' }], attack_mappings: [{ technique: 'T1552.001', element: 'api' }] },
}
const WARNINGS = [
  { severity: 'warning', path: '/model/flows/0/protocol', id: 'calls', message: 'Protocol «wifi» is your own' },
  { severity: 'warning', path: '/model/attack_mappings/0/technique', id: 'T1552.001', message: 'T1552.001 is not in the catalog' },
]

function setup(reply: Reply = { body: { ...PREVIEW, problems: WARNINGS } }) {
  const calls = mockApi(call => {
    if (call.path === '/api/threat-models/validate') return reply
    if (call.path === '/api/threat-models/import') return { body: { model: { id: 'b'.repeat(24) } } }
  })
  const imported = vi.fn()
  renderWithQueries(<ThreatJsonImporter onClose={() => {}} onImported={imported} />)
  return { calls, imported, user: userEvent.setup() }
}

const editor = () => screen.getByRole('textbox', { name: tr('importer.editor') }) as HTMLTextAreaElement
const setText = (value: string) => fireEvent.change(editor(), { target: { value } })
const button = (key: string) => screen.getByRole('button', { name: new RegExp(tr(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) })

describe('locating JSON', () => {
  it('maps pointers to spans and parse errors to an offset', () => {
    const text = '{\n  "a": [1, {"b": "x"}]\n}'
    const result = locate(text)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(text.slice(result.spans.get('/a/1/b')!.start, result.spans.get('/a/1/b')!.end)).toBe('"x"')
      expect(spanOf(result.spans, '/a/1/missing')).toEqual(result.spans.get('/a/1'))
    }
    const broken = locate('{\n  "a": 1\n  "b": 2\n}')
    expect(broken).toMatchObject({ ok: false, offset: 13 })
  })
})

describe('creating a model from JSON', () => {
  it('starts empty, says what to do and keeps the import off', () => {
    setup()
    expect(editor().value).toBe('')
    expect(screen.getByText(tr('importer.empty_state'))).toBeTruthy()
    expect(button('importer.import').hasAttribute('disabled')).toBe(true)
  })

  it('checks the JSON by itself after a pause, without a validate step', async () => {
    const { calls } = setup()
    setText(`${JSON.stringify(DOCUMENT, null, 2)}\n`)
    expect(calls.some(call => call.path === '/api/threat-models/validate')).toBe(false)
    expect(await screen.findByText(tr('importer.status_ready_warnings', { count: 2 }))).toBeTruthy()
    expect(calls.filter(call => call.path === '/api/threat-models/validate')).toHaveLength(1)
    expect(screen.queryByRole('button', { name: /validat/i })).toBeNull()
  })

  it('checks only the last text when edits come quickly', async () => {
    const { calls } = setup({ body: { ...PREVIEW, problems: [] } })
    setText('{"format": "pitangus-threat-model"')
    setText(`${JSON.stringify(DOCUMENT, null, 2)}\n`)
    expect(await screen.findByText(tr('importer.status_ready'))).toBeTruthy()
    const checks = calls.filter(call => call.path === '/api/threat-models/validate')
    expect(checks).toHaveLength(1)
    expect(checks[0].body).toEqual(DOCUMENT)
  })

  it('pretty-prints pasted minified JSON and starts at the top', async () => {
    const { user } = setup()
    editor().focus()
    await user.paste(JSON.stringify(DOCUMENT))
    expect(editor().value).toBe(`${JSON.stringify(DOCUMENT, null, 2)}\n`)
    expect(editor().selectionStart).toBe(0)
    expect(await screen.findByText(tr('importer.status_ready_warnings', { count: 2 }))).toBeTruthy()
  })

  it('leaves invalid pasted text as it is and points at the syntax error', async () => {
    const { user, calls } = setup()
    editor().focus()
    await user.paste('{"format": "pitangus-threat-model" "version": 1}')
    expect(editor().value).toBe('{"format": "pitangus-threat-model" "version": 1}')
    expect(await screen.findByText(tr('importer.status_errors', { count: 1 }))).toBeTruthy()
    const problems = screen.getByRole('region', { name: tr('importer.problems_title') })
    expect(within(problems).getByText(tr('importer.parse_error', { line: 1, column: 36 }))).toBeTruthy()
    expect(calls.some(call => call.path === '/api/threat-models/validate')).toBe(false)
    expect(button('importer.import').hasAttribute('disabled')).toBe(true)
  })

  it('formats JSON with two spaces from the More menu', async () => {
    const { user } = setup()
    setText('{"format":"pitangus-threat-model","version":1}')
    await user.click(button('importer.more'))
    await user.click(await screen.findByRole('menuitem', { name: tr('importer.format') }))
    expect(editor().value).toBe('{\n  "format": "pitangus-threat-model",\n  "version": 1\n}\n')
  })

  it('lists every problem, errors first, each one takes you to its place, and the import stays off', async () => {
    const errors = [{ severity: 'error', path: '/model/flows/0/source', id: 'calls', message: 'source points to «ghost»' }]
    const { user } = setup({ status: 400, body: { error: errors[0].message, problems: [...WARNINGS, ...errors] } })
    const text = `${JSON.stringify(DOCUMENT, null, 2)}\n`
    setText(text)
    expect(await screen.findByText(tr('importer.status_errors', { count: 1 }))).toBeTruthy()
    const problems = screen.getByRole('region', { name: tr('importer.problems_title') })
    const items = within(problems).getAllByRole('button')
    expect(items.map(item => item.textContent)).toEqual([expect.stringContaining('ghost'), expect.stringContaining('wifi'), expect.stringContaining('T1552.001')])
    await user.click(items[0])
    const parsed = locate(text)
    if (!parsed.ok) throw new Error('fixture')
    expect(editor().selectionStart).toBe(parsed.spans.get('/model/flows/0/source')!.start)
    expect(document.activeElement).toBe(editor())
    expect(button('importer.import').hasAttribute('disabled')).toBe(true)
  })

  it('imports with warnings only, and turns the import off again while the text changes', async () => {
    const { user, calls, imported } = setup()
    setText(JSON.stringify(DOCUMENT))
    await screen.findByText(tr('importer.status_ready_warnings', { count: 2 }))
    expect(button('importer.import').hasAttribute('disabled')).toBe(false)
    setText(`${JSON.stringify(DOCUMENT)} `)
    expect(button('importer.import').hasAttribute('disabled')).toBe(true)
    await screen.findByText(tr('importer.status_ready_warnings', { count: 2 }))
    await user.click(button('importer.import'))
    expect(calls.some(call => call.path === '/api/threat-models/import')).toBe(true)
    expect(imported).toHaveBeenCalledWith('b'.repeat(24))
  })

  it('counts only errors and warnings, groups identical problems and folds the minor adjustments', async () => {
    const twoFlows = { ...DOCUMENT, model: { ...DOCUMENT.model, flows: [DOCUMENT.model.flows[0], { id: 'back', source: 'api', target: 'web', protocol: 'https' }] } }
    const problems = [
      { severity: 'warning', path: '/model/flows/0/name', id: 'calls', code: 'cut', message: 'The name was cut' },
      { severity: 'warning', path: '/model/flows/1/name', id: 'back', code: 'cut', message: 'The name was cut' },
      { severity: 'info', path: '/model/flows/0/protocol', id: 'calls', code: 'alias', message: '«component_id» was read as element' },
      { severity: 'info', path: '/model/flows/1/protocol', id: 'back', code: 'alias', message: '«component_id» was read as element' },
      { severity: 'info', path: '/model/attack_mappings/0/technique', id: 'T1552.001', code: 'kept', message: '«x» is kept as a custom property' },
    ]
    const { user } = setup({ body: { ...PREVIEW, problems } })
    const text = `${JSON.stringify(twoFlows, null, 2)}\n`
    setText(text)
    expect(await screen.findByText(tr('importer.status_ready_warnings', { count: 2 }))).toBeTruthy()
    expect(button('importer.import').hasAttribute('disabled')).toBe(false)
    const region = screen.getByRole('region', { name: tr('importer.problems_title') })
    // The two identical warnings are one row, «… in 2 flows», that opens to each flow.
    const group = within(region).getByRole('button', { name: new RegExp('The name was cut') })
    expect(group.textContent).toContain(tr('importer.group_in', { place: tr('count.flows', { count: 2 }) }))
    expect(group.getAttribute('aria-expanded')).toBe('false')
    await user.click(group)
    const places = within(region).getAllByRole('button', { name: /The name was cut/ }).filter(item => item !== group)
    expect(places).toHaveLength(2)
    await user.click(places[1])
    const parsed = locate(text)
    if (!parsed.ok) throw new Error('fixture')
    expect(editor().selectionStart).toBe(parsed.spans.get('/model/flows/1/name')?.start ?? spanOf(parsed.spans, '/model/flows/1/name')!.start)
    // Minor adjustments are folded under their count, grouped too.
    const minor = within(region).getByText(tr('importer.minor', { count: 3 }))
    expect(minor.closest('details')?.open).toBe(false)
    await user.click(minor)
    expect(within(region).getByRole('button', { name: /was read as element/ }).textContent).toContain(tr('importer.group_in', { place: tr('count.flows', { count: 2 }) }))
  })

  it('loads an example and checks it straight away', async () => {
    const { user } = setup({ body: { ...PREVIEW, problems: [] } })
    await user.click(screen.getByRole('button', { name: /STRIDE/ }))
    expect(editor().value).toContain('"format": "pitangus-threat-model"')
    expect(await screen.findByText(tr('importer.status_ready'))).toBeTruthy()
    expect(button('importer.import').hasAttribute('disabled')).toBe(false)
  })

  it('copies a prompt with the real contract: values, rules and a minimal example', async () => {
    const { user } = setup()
    const writeText = vi.spyOn(navigator.clipboard, 'writeText')
    await user.click(button('importer.copy_prompt'))
    const prompt = String((writeText.mock.calls[0] as unknown[])[0])
    for (const value of schema.$defs.flow.properties.protocol.examples) expect(prompt).toContain(value)
    for (const value of schema.$defs.model.properties.methodology.enum) expect(prompt).toContain(value)
    expect(prompt).toContain(schema.$defs.attack_mapping.properties.technique.pattern)
    expect(prompt).toContain('"format": "pitangus-threat-model"')
    expect(prompt).not.toContain('{{')
  })
})
