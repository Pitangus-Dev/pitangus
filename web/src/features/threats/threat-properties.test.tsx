import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { CustomPropertiesField } from '@/features/threats/threat-properties'
import type { CustomProperties } from '@/features/threats/threat-model-types'

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
})
