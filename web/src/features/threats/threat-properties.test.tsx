import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { CustomPropertiesField } from '@/features/threats/threat-properties'
import { AttackTrees } from '@/features/threats/threat-methods'
import type { CustomProperties, Model } from '@/features/threats/threat-model-types'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`threats:${key}`, options)

describe('custom properties', () => {
  it('shows what an import kept, edits text values and refuses a name already used, saying why', async () => {
    const user = userEvent.setup()
    const initial: CustomProperties = { owner: 'Ana', register: [{ id: 'r1', risk: 'Robo' }] }
    let latest = initial
    function Field() {
      const [value, setValue] = useState(initial)
      return <CustomPropertiesField value={value} onChange={next => { latest = next; setValue(next) }} />
    }
    render(<Field />)
    // A structured value is shown as a table, as imported.
    expect(screen.getByRole('table').textContent).toContain('Robo')
    const value = screen.getByRole('textbox', { name: tr('properties.value', { name: 'owner' }) })
    await user.clear(value); await user.type(value, 'Luis')
    expect(latest.owner).toBe('Luis')
    const [name] = screen.getAllByRole('textbox', { name: tr('properties.name') })
    await user.clear(name); await user.type(name, 'register'); await user.tab()
    expect(name.getAttribute('aria-invalid')).toBe('true')
    expect(screen.getByText(tr('properties.name_taken'))).toBeTruthy()
    expect(Object.keys(latest)).toEqual(['owner', 'register'])
    await user.clear(name); await user.type(name, 'responsable{Enter}')
    expect(Object.keys(latest)).toEqual(['responsable', 'register'])
    await user.click(screen.getByRole('button', { name: tr('properties.remove', { name: 'register' }) }))
    expect(latest).toEqual({ responsable: 'Luis' })
  })

  it('keeps numbers as numbers and true/false as booleans while editing', async () => {
    const user = userEvent.setup()
    let latest: CustomProperties = { score: 7.5, reviewed: false }
    function Field() {
      const [value, setValue] = useState(latest)
      return <CustomPropertiesField value={value} onChange={next => { latest = next; setValue(next) }} />
    }
    render(<Field />)
    const score = screen.getByRole('spinbutton', { name: tr('properties.value', { name: 'score' }) })
    await user.clear(score)
    expect(latest.score).toBe(7.5)  // an empty number field isn't saved as text
    await user.type(score, '-12')
    expect(latest.score).toBe(-12)
    await user.click(screen.getByRole('checkbox', { name: tr('properties.value', { name: 'reviewed' }) }))
    expect(latest).toEqual({ score: -12, reviewed: true })
  })

  it('adds a property to an attack tree step that has none', async () => {
    const user = userEvent.setup()
    let latest: Model = { id: 'm', name: 'M', components: [], flows: [], boundaries: [],
      attack_trees: [{ id: 't', goal: 'Goal', nodes: [{ id: 'n', parent: null, text: 'Step', gate: 'or', mitigated: false }] }] }
    function Trees() {
      const [model, setModel] = useState(latest)
      return <AttackTrees model={model} setModel={next => { latest = next; setModel(next) }} />
    }
    render(<Trees />)
    await user.click(screen.getByRole('button', { name: tr('trees.add_property') }))
    expect(latest.attack_trees?.[0].nodes[0].custom_properties).toEqual({ [tr('properties.new_name')]: '' })
    expect(screen.queryByRole('button', { name: tr('trees.add_property') })).toBeNull()  // the field's own button takes over
  })
})
