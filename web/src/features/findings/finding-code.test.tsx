import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { FindingCode } from '@/features/findings/finding-code'

const print = 'b'.repeat(64)
const shown = {
  status: 'shown', reason: null, path: 'app/db.py', commit: 'c'.repeat(40),
  permalink: `https://github.com/acme/api/blob/${'c'.repeat(40)}/app/db.py#L11-L12`,
  lines: [
    { number: 10, text: 'def find(q):', focus: false },
    { number: 11, text: '    token = "••••••"', focus: false, masked: 'span' },
    { number: 12, text: '    cur.execute("SELECT " + q)', focus: true },
    { number: 13, text: '', focus: false, masked: 'line' },
  ],
}

describe('a finding\'s code, read when it opens', () => {
  it('shows the lines the server read, the hidden ones saying so, and links to the file at the commit', async () => {
    const calls = mockApi(call => call.path.startsWith('/api/findings/code') ? { body: shown } : undefined)
    renderWithQueries(<FindingCode runId="run-1" fingerprint={print} />)
    expect(screen.getByRole('status').textContent).toContain(i18n.t('findings:code.loading'))
    expect(await screen.findByText(/cur\.execute/)).toBeTruthy()
    expect(calls[0].path).toBe(`/api/findings/code?run_id=run-1&fingerprint=${print}`)
    expect(screen.getByText(i18n.t('findings:code.masked_line'))).toBeTruthy()
    expect(screen.getByText(i18n.t('findings:code.read_now_masked'))).toBeTruthy()
    expect(screen.getByRole('link').getAttribute('href')).toBe(shown.permalink)
  })

  it('says why the code is not there, and lets the reader try again when the repository could not be read', async () => {
    let attempts = 0
    mockApi(call => {
      if (!call.path.startsWith('/api/findings/code')) return undefined
      attempts += 1
      return { body: attempts === 1 ? { status: 'unavailable', reason: 'repository_unreachable', path: 'a.py', commit: null, lines: [], permalink: null } : shown }
    })
    const user = userEvent.setup()
    renderWithQueries(<FindingCode runId="run-1" fingerprint={print} />)
    expect(await screen.findByText(i18n.t('findings:code.reason.repository_unreachable'))).toBeTruthy()
    await user.click(screen.getByRole('button', { name: i18n.t('findings:code.retry') }))
    expect(await screen.findByText('def find(q):')).toBeTruthy()
  })

  it('shows only where a secret is, and nothing for what has no code', async () => {
    mockApi(call => call.path.includes(`fingerprint=${print}`)
      ? { body: { status: 'withheld', reason: 'secret', path: '.env', commit: 'c'.repeat(40), lines: [], permalink: 'https://github.com/acme/api/blob/x/.env#L3' } }
      : { body: { status: 'unavailable', reason: 'not_code', path: 'package.json', commit: null, lines: [], permalink: null } })
    const { container } = renderWithQueries(<><FindingCode runId="run-1" fingerprint={print} /><FindingCode runId="run-1" fingerprint={'d'.repeat(64)} /></>)
    expect(await screen.findByText(i18n.t('findings:code.reason.secret'))).toBeTruthy()
    expect(container.querySelectorAll('section')).toHaveLength(1)
    expect(container.querySelector('pre')).toBeNull()
  })

  it('names a failure as an error the reader can retry', async () => {
    mockApi(call => call.path.startsWith('/api/findings/code') ? { status: 500, body: { error: 'boom' } } : undefined)
    renderWithQueries(<FindingCode runId="run-1" fingerprint={print} />)
    expect((await screen.findByRole('alert')).textContent).toContain(i18n.t('findings:code.error'))
  })
})
