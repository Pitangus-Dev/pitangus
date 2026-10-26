import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ValueCombobox } from '@/shared/ui/value-combobox'

const OPTIONS = [{ value: 'T1059', label: 'Command and Scripting Interpreter' }]

describe('value combobox', () => {
  it('takes the typed value as text: tags left out, spaces collapsed', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<ValueCombobox label="Technique" value="" options={OPTIONS} onChange={onChange} />)
    await user.type(screen.getByRole('combobox', { name: 'Technique' }), '<b>Own</b>   <i>technique</i><<b>>')
    expect(screen.getByRole('option', { name: /Own technique>/ })).toBeTruthy()
    await user.keyboard('{Enter}')
    expect(onChange).toHaveBeenCalledWith('Own technique>')
  })
})
