import { afterEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { GettingStarted } from '@/features/onboarding/getting-started'

const to = (key: string, options?: Record<string, unknown>) => i18n.t(`onboarding:${key}`, options)
const NOTHING = { mfa: false, github: false, analyzed: false, demo: false, watching: false, alerts: false, admin: true }
// A step's title, with what a screen reader hears after it: (done) or (pending).
const step = (title: string) => screen.getByText(to(title)).textContent

afterEach(() => { localStorage.clear(); vi.unstubAllGlobals() })

describe('getting started', () => {
  it('ticks what the server sees, wherever it was done, and asks again each time it shows', async () => {
    let state = NOTHING
    const calls = mockApi(call => call.path === '/api/onboarding' ? { body: state } : undefined)
    const first = renderWithQueries(<GettingStarted onNavigate={() => {}} />)
    expect(await screen.findByText(to('progress', { done: 0, total: 5 }))).toBeTruthy()
    first.unmount()
    // Done elsewhere (Integrations, the account page, the CLI): this card never clicked anything.
    state = { ...NOTHING, mfa: true, github: true, analyzed: true }
    renderWithQueries(<GettingStarted onNavigate={() => {}} />)
    expect(await screen.findByText(to('progress', { done: 3, total: 5 }))).toBeTruthy()
    expect(step('steps.github.title')).toBe(`${to('steps.github.title')} ${to('done')}`)
    expect(step('steps.alerts.title')).toBe(`${to('steps.alerts.title')} ${to('pending')}`)
    expect(calls.filter(call => call.path === '/api/onboarding')).toHaveLength(2)
  })

  it('stays out of the way once every step is done, and when dismissed', async () => {
    mockApi(call => call.path === '/api/onboarding' ? { body: NOTHING } : undefined)
    const user = userEvent.setup()
    const view = renderWithQueries(<GettingStarted onNavigate={() => {}} />)
    await user.click(await screen.findByRole('button', { name: to('hide') }))
    expect(screen.queryByText(to('title'))).toBeNull()
    expect(localStorage.getItem('pitangus-getting-started-hidden')).toBe('1')
    view.unmount()
    localStorage.clear()
    const calls = mockApi(call => call.path === '/api/onboarding' ? { body: { ...NOTHING, mfa: true, github: true, analyzed: true, watching: true, alerts: true } } : undefined)
    renderWithQueries(<GettingStarted onNavigate={() => {}} />)
    await waitFor(() => expect(calls).toHaveLength(1))
    expect(screen.queryByText(to('title'))).toBeNull()
  })
})
