import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { ConfirmProvider } from '@/shared/ui/confirm-dialog'
import { useConfirm } from '@/shared/ui/confirm'

function Asker() {
  const confirm = useConfirm()
  const [answer, setAnswer] = useState('none')
  return <><button type="button" onClick={() => void confirm({ title: 'Delete it?', description: 'This can\'t be undone.', confirmLabel: 'Delete', destructive: true }).then(ok => setAnswer(String(ok)))}>Ask</button>
    <output>{answer}</output></>
}

const setup = () => {
  const user = userEvent.setup()
  render(<ConfirmProvider><Asker /></ConfirmProvider>)
  return user
}

describe('confirm dialog', () => {
  it('resolves true when confirmed', async () => {
    const user = setup()
    await user.click(screen.getByRole('button', { name: 'Ask' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Delete it?' })
    expect(dialog.textContent).toContain('This can\'t be undone.')
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('true'))
  })

  it('starts on the safe option and resolves false on cancel', async () => {
    const user = setup()
    await user.click(screen.getByRole('button', { name: 'Ask' }))
    await screen.findByRole('alertdialog')
    const cancel = screen.getByRole('button', { name: 'Cancel' })
    await waitFor(() => expect(document.activeElement).toBe(cancel))
    await user.click(cancel)
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('false'))
  })

  it('resolves false on Escape', async () => {
    const user = setup()
    await user.click(screen.getByRole('button', { name: 'Ask' }))
    await screen.findByRole('alertdialog')
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('false'))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull())
  })
})
