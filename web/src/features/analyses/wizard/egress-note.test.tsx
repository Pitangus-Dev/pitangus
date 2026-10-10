import { describe, expect, it } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { EgressNote } from '@/features/analyses/wizard/egress-note'

const tr = (key: string) => i18n.t(`analyses:${key}`)
const UNKNOWN = { ips: [], source: null, detected_at: null }

describe('outgoing address note', () => {
  it('members without an address are told who to ask, with nothing to click', () => {
    mockApi(() => undefined)
    renderWithQueries(<EgressNote egress={UNKNOWN} admin={false} />)
    expect(screen.getByText(tr('review.egress.ask_admin'))).toBeTruthy()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('an administrator detects it on purpose, and a failure is said', async () => {
    let fail = true
    const calls = mockApi(call => {
      if (call.path === '/api/domains/egress') return fail ? { status: 502, body: { error: 'The echo service failed' } } : { body: { ips: ['8.8.8.8'], source: 'detected', detected_at: '2026-10-10T00:00:00Z' } }
      return { body: { items: [], total: 0, limit: 20, dast: true } }
    })
    const user = userEvent.setup()
    renderWithQueries(<EgressNote egress={UNKNOWN} admin />)
    expect(calls.some(call => call.path === '/api/domains/egress')).toBe(false)
    await user.click(screen.getByRole('button', { name: tr('review.egress.detect') }))
    expect((await screen.findByRole('alert')).textContent).toContain('echo service')
    fail = false
    await user.click(screen.getByRole('button', { name: tr('review.egress.detect') }))
    await waitFor(() => expect(calls.filter(call => call.path === '/api/domains/egress')).toHaveLength(2))
    expect(calls.find(call => call.path === '/api/domains/egress')).toMatchObject({ method: 'POST', action: 'detect-egress' })
  })
})
