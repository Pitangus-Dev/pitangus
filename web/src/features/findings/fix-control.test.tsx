import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { FixControlNotices } from '@/features/findings/fix-control'

const tr = (key: string, options?: Record<string, unknown>) => i18n.t(`findings:${key}`, options)
const HOLD = { mode: 'on', hold: { count: 12, at: '2026-10-12T10:00:00Z', run: 'r'.repeat(32) }, released: null, unseen_warn_scans: 3 }
const COUNTS = { open: 4, fixed: 1, suppressed: 0, from_pr: 0, excluded: 0, unverified: 2, unverified_stale: 2 }

describe('how an asset gets its findings fixed', () => {
  it('says what is held back and lets an admin apply it after confirming', async () => {
    const calls = mockApi(call => call.path === '/api/assets/fix-hold' ? { body: { released: 12 } } : undefined)
    const changed = vi.fn()
    const user = userEvent.setup()
    renderWithQueries(<FixControlNotices assetKey="github#7" control={HOLD} counts={COUNTS} admin onChanged={changed} />)
    expect(screen.getByText(tr('control.unverified', { count: 2, number: '2', scans: 3 }))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: tr('control.release') }))
    const question = await screen.findByRole('alertdialog')
    await user.click(within(question).getByRole('button', { name: tr('control.release') }))
    await waitFor(() => expect(changed).toHaveBeenCalled())
    expect(calls.find(call => call.path === '/api/assets/fix-hold')).toEqual({ method: 'POST', path: '/api/assets/fix-hold', action: 'release-fix-hold', body: { asset: 'github#7' } })
  })

  it('says why the fixes are held, and warns at once about findings a configuration change left unchecked', () => {
    const reason = { kind: 'too_many', run: 'r'.repeat(32), at: '2026-10-12T10:00:00Z', count: 72, open: 80, minimum: 10, percent: 30 }
    renderWithQueries(<FixControlNotices assetKey="github#7" control={{ ...HOLD, hold: { ...HOLD.hold, count: 72, reason } }}
      counts={{ ...COUNTS, unverified_stale: 0, unverified_configuration: 5 }} admin={false} onChanged={() => {}} />)
    const [held, unchecked] = screen.getAllByRole('status')
    expect(held.textContent).toContain('72')
    expect(held.textContent).toContain('80')
    expect(held.textContent).toContain('30')
    expect(unchecked.textContent).toBe(tr('control.configuration', { count: 5, number: '5' }))
  })

  it('shows members the hold without the action, and nothing when there is nothing to say', () => {
    const { unmount } = renderWithQueries(<FixControlNotices assetKey="github#7" control={HOLD} counts={{ ...COUNTS, unverified_stale: 0 }} admin={false} onChanged={() => {}} />)
    expect(screen.queryByRole('button', { name: tr('control.release') })).toBeNull()
    expect(screen.getAllByRole('status')).toHaveLength(1)
    unmount()
    renderWithQueries(<FixControlNotices assetKey="github#7" control={{ ...HOLD, hold: null }} counts={{ ...COUNTS, unverified_stale: 0 }} admin onChanged={() => {}} />)
    expect(screen.queryByRole('status')).toBeNull()
  })
})
