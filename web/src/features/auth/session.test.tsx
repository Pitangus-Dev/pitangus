import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { act } from 'react'
import i18n from '@/shared/i18n'
import { UNAUTHORIZED_EVENT } from '@/shared/api/http'
import { mockApi } from '@/shared/test/api'
import { SessionGate } from '@/features/auth/session'
import { PublicDemoNotice } from '@/features/auth/public-demo'

const USER = { id: 'u1', username: 'ana', display_name: 'Ana', role: 'member', totp_enabled: true, last_login_at: null }
const signedIn = { authenticated: true, user: USER, mfa: true, totp_required: false }
const signedOut = { authenticated: false, setup_required: false }
const app = () => <SessionGate>{user => <p>inside as {user.username}</p>}</SessionGate>

describe('sign-in', () => {
  it('asks for the second factor and lets the person in', async () => {
    let session: unknown = signedOut
    const calls = mockApi(call => {
      if (call.path === '/api/auth/session') return { body: session }
      if (call.path === '/api/auth/login') return { body: { step: 'totp', challenge: 'challenge-1' } }
      if (call.path === '/api/auth/totp') { session = signedIn; return { body: { step: 'done' } } }
    })
    const user = userEvent.setup()
    render(app())
    await user.type(await screen.findByLabelText(i18n.t('auth:fields.username')), 'ana')
    await user.type(screen.getByLabelText(i18n.t('auth:fields.password')), 'a long passphrase')
    await user.click(screen.getByRole('button', { name: i18n.t('auth:login.enter') }))
    await user.type(await screen.findByLabelText(i18n.t('auth:fields.code')), ' 123456 ')
    await user.click(screen.getByRole('button', { name: i18n.t('auth:login.verify') }))

    expect(await screen.findByText('inside as ana')).toBeTruthy()
    const login = calls.find(call => call.path === '/api/auth/login')
    expect(login).toEqual({ method: 'POST', path: '/api/auth/login', action: 'login', body: { username: 'ana', password: 'a long passphrase' } })
    // The code goes trimmed, with the challenge the server handed out; the password never goes twice.
    expect(calls.find(call => call.path === '/api/auth/totp')?.body).toEqual({ challenge: 'challenge-1', code: '123456' })
  })

  it('shows why a sign-in failed and stays on the form', async () => {
    mockApi(call => {
      if (call.path === '/api/auth/session') return { body: signedOut }
      if (call.path === '/api/auth/login') return { status: 401, body: { error: 'Wrong username or password.' } }
    })
    const user = userEvent.setup()
    render(app())
    await user.type(await screen.findByLabelText(i18n.t('auth:fields.username')), 'ana')
    await user.type(screen.getByLabelText(i18n.t('auth:fields.password')), 'not the passphrase')
    await user.click(screen.getByRole('button', { name: i18n.t('auth:login.enter') }))

    expect((await screen.findByRole('alert')).textContent).toBe('Wrong username or password.')
    // A failed sign-in is not an expired session.
    expect(screen.queryByText(i18n.t('auth:session_expired'))).toBeNull()
  })

  it('sends the person back to sign in when the session expires', async () => {
    mockApi(call => call.path === '/api/auth/session' ? { body: signedIn } : undefined)
    render(app())
    expect(await screen.findByText('inside as ana')).toBeTruthy()
    act(() => { window.dispatchEvent(new Event(UNAUTHORIZED_EVENT)) })
    expect(await screen.findByText(i18n.t('auth:session_expired'))).toBeTruthy()
    expect(screen.queryByText('inside as ana')).toBeNull()
  })
})

describe('public demo', () => {
  const demo = { username: 'demo', password: 'lapis-labs-visita-publica' }

  it('shows the published credentials already filled in and tells the app it is the demo', async () => {
    let session: unknown = { ...signedOut, public_demo: demo }
    const calls = mockApi(call => {
      if (call.path === '/api/auth/session') return { body: session }
      if (call.path === '/api/auth/login') { session = { ...signedIn, user: { ...USER, username: 'demo' }, public_demo: demo }; return { body: { step: 'done' } } }
    })
    const user = userEvent.setup()
    render(<SessionGate>{(person, actions) => <p>inside as {person.username}{actions.publicDemo ? ' (demo)' : ''}</p>}</SessionGate>)
    expect((await screen.findByLabelText(i18n.t('auth:fields.username')) as HTMLInputElement).value).toBe('demo')
    expect((screen.getByLabelText(i18n.t('auth:fields.password')) as HTMLInputElement).value).toBe(demo.password)
    expect(screen.getByText(demo.password)).toBeTruthy()
    expect(screen.queryByText(i18n.t('auth:login.forgot'))).toBeNull()
    await user.click(screen.getByRole('button', { name: i18n.t('auth:login.enter') }))

    expect(await screen.findByText('inside as demo (demo)')).toBeTruthy()
    expect(calls.find(call => call.path === '/api/auth/login')?.body).toEqual({ username: 'demo', password: demo.password })
  })

  it('says nothing about a demo on any other server', async () => {
    mockApi(call => call.path === '/api/auth/session' ? { body: signedIn } : undefined)
    render(<SessionGate>{(person, actions) => <p>inside as {person.username}{actions.publicDemo ? ' (demo)' : ''}</p>}</SessionGate>)
    expect(await screen.findByText('inside as ana')).toBeTruthy()
  })

  it('the banner says it is read-only with made-up data and links to the real thing', () => {
    render(<PublicDemoNotice />)
    const text = i18n.t('auth:public_demo.banner').match(/<install>(.*)<\/install>/)?.[1] ?? ''
    const link = screen.getByRole('link', { name: name => name.startsWith(text) && name.endsWith(i18n.t('sources:new_tab')) })
    expect(link.getAttribute('href')).toBe('https://github.com/Pitangus-Dev/pitangus')
    expect(link.getAttribute('rel')).toBe('noopener noreferrer')
    expect(document.body.textContent).toContain('Lapis Labs')
    expect(document.body.textContent).toContain(i18n.t('auth:public_demo.banner').split(':')[0])
  })
})
