import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { SelectField } from '@/shared/ui/select-field'

const shown = (trigger: HTMLElement) => trigger.querySelector('[data-slot=select-value]')?.textContent

function Field({ initial = '' }: { initial?: string }) {
  const [value, setValue] = useState(initial)
  return <><label htmlFor="pick">Severity</label>
    <SelectField id="pick" value={value} onValueChange={setValue} placeholder="Any" options={[{ value: 'high', label: 'High' }, { value: 'low', label: 'Low' }]}
      groups={[{ label: 'Other', options: [{ value: 'x', label: 'Extra' }] }]} />
    <output>{value || 'empty'}</output></>
}

// The list depends on the choice: the first option leaves once something else is chosen.
function Shrinking() {
  const [value, setValue] = useState('a')
  const options = ['a', 'b', 'c'].filter(item => item === value || item !== 'a').map(item => ({ value: item, label: item.toUpperCase() }))
  return <><SelectField aria-label="Pick" value={value} onValueChange={setValue} options={options} /><output>{value || 'empty'}</output></>
}

describe('select field', () => {
  it('is named by its label and shows the chosen label, not the value', async () => {
    const user = userEvent.setup()
    render(<Field />)
    const trigger = screen.getByRole('combobox', { name: 'Severity' })
    expect(screen.getByLabelText('Severity')).toBe(trigger)
    expect(shown(trigger)).toBe('Any')
    expect(trigger.hasAttribute('data-placeholder')).toBe(true)
    await user.click(trigger)
    await user.click(await screen.findByRole('option', { name: 'High' }))
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('high'))
    expect(shown(trigger)).toBe('High')
    expect(trigger.hasAttribute('data-placeholder')).toBe(false)
  })

  it('offers grouped options and the empty choice back', async () => {
    const user = userEvent.setup()
    render(<Field initial="x" />)
    const trigger = screen.getByRole('combobox', { name: 'Severity' })
    expect(shown(trigger)).toBe('Extra')
    await user.click(trigger)
    expect(await screen.findByRole('group', { name: 'Other' })).toBeTruthy()
    await user.click(screen.getByRole('option', { name: 'Any' }))
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('empty'))
  })

  it('keeps the choice when an option before it leaves the list', async () => {
    const user = userEvent.setup()
    render(<Shrinking />)
    const trigger = screen.getByRole('combobox', { name: 'Pick' })
    await user.click(trigger)
    await user.click(await screen.findByRole('option', { name: 'B' }))
    await waitFor(() => expect(trigger.getAttribute('aria-expanded')).toBe('false'))
    await new Promise(resolve => setTimeout(resolve, 100))
    expect(screen.getByRole('status').textContent).toBe('b')
    expect(shown(trigger)).toBe('B')
  })
})
