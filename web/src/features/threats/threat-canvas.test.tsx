import { useState } from 'react'
import { beforeAll, describe, expect, it } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { ThreatCanvas } from '@/features/threats/threat-canvas'
import { labelSpots } from '@/features/threats/threat-layout'
import type { Catalog, Component, Model } from '@/features/threats/threat-model-types'
import { mockReactFlowLayout } from '@/shared/test/react-flow'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`threats:${key}`, options)

beforeAll(mockReactFlowLayout)

const part = (id: string, name: string, x: number): Component =>
  ({ id, name, kind: 'service', data: [], internet_facing: false, authenticates: false, encrypted_at_rest: false, position: { x, y: 80 } })
const MODEL: Model = { id: 'm', name: 'M', boundaries: [], components: [part('web', 'Web', 40), part('api', 'API', 440)],
  flows: [{ id: 'web-api', source: 'web', target: 'api', protocol: 'https', data: [], authenticated: true, encrypted: true }] }
const CATALOG = { models: [], assets: [], kinds: { service: 'Service' }, protocols: [], classifications: {}, workspace: {},
  methods: { methodologies: {}, linddun: {}, pasta_stages: [], attack: {} } } as unknown as Catalog

function Harness({ initial = MODEL, readOnly = false }: { initial?: Model; readOnly?: boolean }) {
  const [model, setModel] = useState(initial)
  return <><ThreatCanvas model={model} setModel={setModel} threats={[]} catalog={CATALOG} readOnly={readOnly} />
    <output data-testid="offset">{JSON.stringify(model.flows[0].label_offset ?? null)}</output></>
}
const offset = () => JSON.parse(screen.getByTestId('offset').textContent ?? 'null') as { x: number; y: number } | null
const label = async () => {
  await waitFor(() => expect(document.querySelector('.tm-flow-label')).not.toBeNull())
  return document.querySelector<HTMLElement>('.tm-flow-label')!
}
const at = (element: HTMLElement) => ({ x: Number(element.dataset.x), y: Number(element.dataset.y) })

describe('flow labels on the diagram', () => {
  it('drags a label: the model keeps its offset from the line, and Escape cancels a drag', async () => {
    render(<Harness />)
    const element = await label()
    const start = at(element)
    act(() => { fireEvent.pointerDown(element, { button: 0, clientX: 100, clientY: 100, pointerId: 1 }) })
    act(() => { fireEvent.pointerMove(element, { clientX: 140, clientY: 160, pointerId: 1 }) })
    // While it moves, a thin line ties it to the middle of its flow.
    expect(document.querySelector('.tm-label-link')).not.toBeNull()
    act(() => { fireEvent.keyDown(window, { key: 'Escape' }) })
    act(() => { fireEvent.pointerUp(element, { pointerId: 1 }) })
    expect(offset()).toBeNull()
    expect(at(await label())).toEqual(start)

    act(() => { fireEvent.pointerDown(element, { button: 0, clientX: 100, clientY: 100, pointerId: 1 }) })
    act(() => { fireEvent.pointerMove(element, { clientX: 140, clientY: 160, pointerId: 1 }) })
    act(() => { fireEvent.pointerUp(element, { pointerId: 1 }) })
    const moved = offset()!
    expect(moved).not.toBeNull()
    const now = at(await label())
    // The pointer's movement on screen, in the diagram's scale (fitView zooms it).
    expect(now.x).toBeGreaterThan(start.x)
    expect((now.y - start.y) / (now.x - start.x)).toBeCloseTo(1.5, 1)
  })

  it('moves a label with the keyboard, further with Shift, and puts it back', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const element = await label()
    expect(element.getAttribute('aria-label')).toBe(tr('canvas.aria.flow_label', { label: '1 · HTTPS' }))
    element.focus()
    await user.keyboard('{ArrowRight}')
    const first = offset()!
    expect(first).toEqual({ x: 8, y: 0 })  // from the automatic place, here the line's midpoint
    await user.keyboard('{Shift>}{ArrowDown}{/Shift}')
    expect(offset()).toEqual({ x: first.x, y: first.y + 40 })
    // Double-click resets it to the automatic place.
    await user.dblClick(await label())
    expect(offset()).toBeNull()
  })

  it('resets the label from the flow panel', async () => {
    const user = userEvent.setup()
    render(<Harness initial={{ ...MODEL, flows: [{ ...MODEL.flows[0], label_offset: { x: 0, y: -80 } }] }} />)
    await user.click(await label())  // a click without moving selects the flow
    await user.click(screen.getByRole('button', { name: tr('inspector.reset_label') }))
    expect(offset()).toBeNull()
    expect(screen.queryByRole('button', { name: tr('inspector.reset_label') })).toBeNull()
  })

  it("doesn't let someone who can't edit move a label", async () => {
    render(<Harness readOnly initial={{ ...MODEL, flows: [{ ...MODEL.flows[0], label_offset: { x: 10, y: 10 } }] }} />)
    const element = await label()
    expect(element.getAttribute('tabindex')).toBeNull()
    act(() => { fireEvent.pointerDown(element, { button: 0, clientX: 100, clientY: 100, pointerId: 1 }) })
    act(() => { fireEvent.pointerMove(element, { clientX: 200, clientY: 200, pointerId: 1 }) })
    act(() => { fireEvent.pointerUp(element, { pointerId: 1 }) })
    fireEvent.doubleClick(element)
    expect(offset()).toEqual({ x: 10, y: 10 })
    expect(screen.queryByRole('button', { name: tr('inspector.reset_label') })).toBeNull()
  })

  it('places the other labels around one the team moved', () => {
    const rect = (x: number) => ({ x, y: 0, width: 184, height: 64 })
    const edge = { id: 'a', source: rect(0), target: rect(400), sourceSide: 'right' as const, targetSide: 'left' as const, text: '1 · https' }
    // Alone, the label sits in the middle; with a moved label right there, it moves along its curve.
    expect(labelSpots([edge], [])).toEqual({ a: 0.5 })
    const moved = { ...edge, id: 'b', text: '2 · https', moved: { x: 0, y: 0 } }
    const spots = labelSpots([edge, moved], [])
    expect(spots.b).toBe(0.5)
    expect(spots.a).not.toBe(0.5)
  })
})
