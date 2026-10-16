import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { AiPrompt } from '@/features/findings/ai-prompt'

describe('copy prompt for your AI', () => {
  it('copies the prompt the server built for this finding, and falls back to the text when the clipboard says no', async () => {
    const calls = mockApi(call => call.path.startsWith('/api/findings/prompt') ? { body: { prompt: 'Fix this security finding in my code.' } } : undefined)
    const user = userEvent.setup()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    renderWithQueries(<AiPrompt runId="run-1" fingerprint={'a'.repeat(64)} />)
    const button = screen.getByRole('button', { name: i18n.t('findings:ai_prompt.copy') })
    await waitFor(() => expect(button.getAttribute('aria-disabled')).toBe('false'))
    expect(calls[0].path).toBe(`/api/findings/prompt?run_id=run-1&fingerprint=${'a'.repeat(64)}`)
    await user.click(button)
    expect(writeText).toHaveBeenCalledWith('Fix this security finding in my code.')
    expect(await screen.findByRole('button', { name: i18n.t('findings:ai_prompt.copied') })).toBeTruthy()

    writeText.mockRejectedValueOnce(new Error('denied'))
    await user.click(screen.getByRole('button'))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe('Fix this security finding in my code.')
  })

  it('puts the code the reader opened between the server\'s parts, a hidden line saying so', async () => {
    mockApi(call => call.path.startsWith('/api/findings/prompt')
      ? { body: { prompt: 'intro\n\nfix\n', before: 'intro', heading: 'The code:', language: 'python', after: 'fix' } }
      : call.path.startsWith('/api/findings/code')
        ? { body: { status: 'shown', reason: null, path: 'a.py', commit: 'c'.repeat(40), permalink: null,
          lines: [{ number: 1, text: 'eval(q)', focus: true }, { number: 2, text: '', focus: false, masked: 'line' }] } }
        : undefined)
    const user = userEvent.setup()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    renderWithQueries(<AiPrompt runId="run-1" fingerprint={'a'.repeat(64)} withCode />)
    const button = screen.getByRole('button', { name: i18n.t('findings:ai_prompt.copy') })
    await waitFor(() => expect(button.getAttribute('aria-disabled')).toBe('false'))
    await waitFor(async () => {
      await user.click(button)
      expect(writeText).toHaveBeenLastCalledWith(`intro\n\nThe code:\n\`\`\`python\neval(q)\n${i18n.t('findings:code.masked_line')}\n\`\`\`\n\nfix\n`)
    })
  })
})
