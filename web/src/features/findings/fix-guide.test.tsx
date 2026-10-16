import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import i18n from '@/shared/i18n'
import { FixSection, type FixGuide } from '@/features/findings/fix-guide'

const tf = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)

describe('fix guide', () => {
  it('starts with the whole move for a transitive dependency, then the commands in order', () => {
    const fix: FixGuide = { kind: 'dependency', example: null, action: 'Update rustls-webpki to 0.103.13; if it stays below, update reqwest, which brings it in.',
      steps: ['rustls-webpki 0.103.10 comes from reqwest 0.12.9 through rustls 0.23.20.'],
      commands: [{ label: 'Update', action: 'update', code: 'cargo update -p rustls-webpki@0.103.10 --precise 0.103.13' },
        { label: 'Check that it shows 0.103.13 or later', action: 'check', code: 'cargo tree --invert rustls-webpki' },
        { label: 'If it stays below 0.103.13, update reqwest', action: 'update', code: 'cargo update -p reqwest' }] }
    render(<FixSection fix={fix} remediation="" />)
    const text = document.body.textContent ?? ''
    const order = [fix.action!, fix.steps[0], ...fix.commands.map(command => command.code)].map(part => text.indexOf(part))
    expect(order.every(index => index >= 0)).toBe(true)
    expect(order).toEqual([...order].sort((a, b) => a - b))
  })

  it('says what a dependency guide is built from, and nothing of the sort without commands', () => {
    const { unmount } = render(<FixSection remediation="" fix={{ kind: 'dependency', steps: [], example: null, commands: [{ label: 'Update', action: 'update', code: 'poetry update starlette' }] }} />)
    expect(screen.getByText(tf('fix.basis'))).toBeTruthy()
    unmount()
    render(<FixSection remediation="" fix={{ kind: 'dependency', steps: ['No fixed version has been published.'], commands: [], example: null }} />)
    expect(screen.queryByText(tf('fix.basis'))).toBeNull()
  })

  it('says which file a snippet goes in', () => {
    render(<FixSection remediation="" fix={{ kind: 'dependency', steps: [], commands: [], example: { language: 'json', file: 'package.json', before: '', after: '{"overrides": {}}' } }} />)
    expect(screen.getByText(tf('fix.example_in', { file: 'package.json' }))).toBeTruthy()
  })
})
