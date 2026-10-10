import { useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, LoaderCircle, MoreHorizontal, UserRound } from 'lucide-react'
import { apiPost } from '@/shared/api/client'
import { keys, type DomainTestUser } from '@/shared/api/queries'
import { formatDay } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { useConfirm } from '@/shared/ui/confirm'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, dialogFullOnMobile } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { SelectField } from '@/shared/ui/select-field'
import type { Domain } from '@/features/domains/domains'
import { METHOD_LABEL, TEST_USERS_MAX, methodOf, testUserSummary, type Editing, type LoginMethod } from '@/features/domains/test-users-model'

const DIGITS = ['6', '7', '8']
const PERIODS = ['15', '30', '60', '90', '120']
const ALGORITHMS = ['SHA1', 'SHA256', 'SHA512']
type Page = { items: Domain[] }
type Saved = { test_users: DomainTestUser[] }

// Puts the answer's list into the cached domain at once (the row's count with it), then refreshes the rest.
function useStore(domain: Domain) {
  const queryClient = useQueryClient()
  return (saved: Saved) => {
    queryClient.setQueryData<Page>(keys.domains, page => page && { ...page, items: page.items.map(item => item.id === domain.id
      ? { ...item, test_users: saved.test_users, test_user_count: saved.test_users.length } : item) })
    void queryClient.invalidateQueries({ queryKey: keys.domains })
  }
}

// "Add test user ▾": the two ways a scan can sign in. Codes by email and magic links need an inbox nobody here reads.
export function AddTestUserMenu({ onPick, disabled, variant = 'outline' }: { onPick: (method: LoginMethod) => void; disabled?: boolean; variant?: 'outline' | 'brand' }) {
  const { t } = useTranslation('sources')
  return <Menu><MenuTrigger render={<Button variant={variant} size="sm" disabled={disabled} />}>{t('domains.test_users.add')}<ChevronDown className="size-3.5" aria-hidden /></MenuTrigger>
    <MenuContent align="start">
      <MenuItem onClick={() => onPick('password')}>{t('domains.test_users.method.password')}</MenuItem>
      <MenuItem onClick={() => onPick('password_totp')}>{t('domains.test_users.method.password_totp')}</MenuItem>
    </MenuContent></Menu>
}

// Adds or changes one test user. Secrets are write-only: when changing one, a blank password or key keeps the saved one.
export function TestUserDialog({ domain, editing, onClose, onSaved }: { domain: Domain; editing: Editing | null; onClose: () => void; onSaved?: (user: DomainTestUser) => void }) {
  const { t } = useTranslation('sources')
  return <Dialog open={editing !== null} onOpenChange={open => { if (!open) onClose() }}><DialogContent className={`max-w-lg ${dialogFullOnMobile}`}>
    {editing && <>
      <DialogHeader>
        <DialogTitle>{t(editing.user ? 'domains.test_users.edit_title' : 'domains.test_users.add_title')}</DialogTitle>
        <DialogDescription>{t(METHOD_LABEL[editing.method])}</DialogDescription>
      </DialogHeader>
      <TestUserForm key={`${editing.user?.id ?? 'new'}-${editing.method}`} domain={domain} editing={editing} onCancel={onClose}
        onSaved={user => { onSaved?.(user); onClose() }} />
    </>}
  </DialogContent></Dialog>
}

function TestUserForm({ domain, editing, onCancel, onSaved }: { domain: Domain; editing: Editing; onCancel: () => void; onSaved: (user: DomainTestUser) => void }) {
  const { t } = useTranslation('sources')
  const store = useStore(domain)
  const current = editing.user
  const totp = editing.method === 'password_totp'
  // A user switching to TOTP has no saved key yet: it must be typed.
  const keyRequired = totp && (!current || current.method !== 'password_totp')
  const [name, setName] = useState(current?.name ?? '')
  const [username, setUsername] = useState(current?.username ?? '')
  const [password, setPassword] = useState('')
  const [secret, setSecret] = useState('')
  const [digits, setDigits] = useState('6')
  const [period, setPeriod] = useState('30')
  const [algorithm, setAlgorithm] = useState('SHA1')
  const [loginUrl, setLoginUrl] = useState(current?.login_url ?? '')
  const [checkUrl, setCheckUrl] = useState(current?.check_url ?? '')
  const [notes, setNotes] = useState(current?.notes ?? '')
  const [appliesTo, setAppliesTo] = useState(current?.applies_to ?? domain.host)
  const save = useMutation({
    mutationFn: () => apiPost('/api/domains/test-users', 'domain-test-users', {
      domain_id: domain.id, op: 'save', ...(current ? { id: current.id } : {}), name: name.trim(), method: editing.method, username: username.trim(),
      ...(password ? { password } : {}),
      ...(totp && secret ? { totp: { secret: secret.trim(), digits: Number(digits), period: Number(period), algorithm: algorithm as 'SHA1' | 'SHA256' | 'SHA512' } } : {}),
      login_url: loginUrl.trim(), check_url: checkUrl.trim(), notes: notes.trim(), applies_to: appliesTo.trim() || domain.host,
    }),
    onSuccess: saved => {
      store(saved)
      const user = saved.test_users.find(item => item.id === current?.id) ?? saved.test_users.find(item => item.name.toLowerCase() === name.trim().toLowerCase())
      if (user) onSaved(user)
    },
  })
  const ready = !!name.trim() && !!username.trim() && (current ? true : !!password) && (!keyRequired || !!secret.trim())
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (ready && !save.isPending) save.mutate() }
  const keep = current ? t('domains.test_users.keep_saved') : undefined

  return <form onSubmit={submit} className="space-y-4">
    <Field id="test-user-name" label={t('domains.test_users.name')}>
      <Input id="test-user-name" autoFocus required maxLength={80} value={name} onChange={event => setName(event.target.value)} placeholder={t('domains.test_users.name_placeholder')}
        autoComplete="off" className="border-app-line bg-app-soft" />
    </Field>
    <Field id="test-user-username" label={t('domains.test_users.username')}>
      <Input id="test-user-username" required maxLength={256} value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" spellCheck={false}
        className="border-app-line bg-app-soft" />
    </Field>
    <Field id="test-user-password" label={t('domains.test_users.password')} hint={keep}>
      <Input id="test-user-password" type="password" required={!current} maxLength={1024} value={password} onChange={event => setPassword(event.target.value)} autoComplete="new-password"
        spellCheck={false} aria-describedby={keep ? 'test-user-password-hint' : undefined} className="border-app-line bg-app-soft" />
    </Field>
    {totp && <Field id="test-user-totp" label={t('domains.test_users.totp_secret')} hint={keyRequired ? t('domains.test_users.totp_hint') : keep}>
      <Input id="test-user-totp" type="password" required={keyRequired} maxLength={300} value={secret} onChange={event => setSecret(event.target.value)} autoComplete="off"
        spellCheck={false} aria-describedby="test-user-totp-hint" className="border-app-line bg-app-soft font-mono" />
    </Field>}
    <details className="group">
      <summary className="flex min-h-6 cursor-pointer list-none items-center gap-1.5 text-sm text-app-secondary"><ChevronRight className="size-4 motion-safe:transition group-open:rotate-90" aria-hidden />{t('domains.test_users.advanced')}</summary>
      <div className="mt-3 space-y-4">
        <Field id="test-user-login-url" label={t('domains.test_users.login_url')} hint={t('domains.test_users.login_url_hint')}>
          <Input id="test-user-login-url" inputMode="url" maxLength={2000} value={loginUrl} onChange={event => setLoginUrl(event.target.value)} placeholder={`https://${domain.host}/login`}
            autoComplete="off" spellCheck={false} aria-describedby="test-user-login-url-hint" className="border-app-line bg-app-soft font-mono" />
        </Field>
        <Field id="test-user-check-url" label={t('domains.test_users.check_url')} hint={t('domains.test_users.check_url_hint')}>
          <Input id="test-user-check-url" inputMode="url" maxLength={2000} value={checkUrl} onChange={event => setCheckUrl(event.target.value)} placeholder={`https://${domain.host}/account`}
            autoComplete="off" spellCheck={false} aria-describedby="test-user-check-url-hint" className="border-app-line bg-app-soft font-mono" />
        </Field>
        <Field id="test-user-applies-to" label={t('domains.test_users.applies_to')} hint={t('domains.test_users.applies_to_hint')}>
          <Input id="test-user-applies-to" maxLength={253} value={appliesTo} onChange={event => setAppliesTo(event.target.value)} autoComplete="off" spellCheck={false}
            aria-describedby="test-user-applies-to-hint" className="border-app-line bg-app-soft font-mono" />
        </Field>
        <Field id="test-user-notes" label={t('domains.test_users.notes')}>
          <textarea id="test-user-notes" rows={2} maxLength={1000} value={notes} onChange={event => setNotes(event.target.value)}
            className="w-full rounded-lg border border-app-line bg-app-soft p-3 text-sm focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50" />
        </Field>
        {totp && <div className="grid gap-3 sm:grid-cols-3">
          <Field id="test-user-digits" label={t('domains.test_users.digits')}><SelectField id="test-user-digits" value={digits} onValueChange={setDigits} options={DIGITS.map(value => ({ value, label: value }))} /></Field>
          <Field id="test-user-period" label={t('domains.test_users.period')}><SelectField id="test-user-period" value={period} onValueChange={setPeriod} options={PERIODS.map(value => ({ value, label: t('domains.test_users.seconds', { count: Number(value) }) }))} /></Field>
          <Field id="test-user-algorithm" label={t('domains.test_users.algorithm')}><SelectField id="test-user-algorithm" value={algorithm} onValueChange={setAlgorithm} options={ALGORITHMS.map(value => ({ value, label: value }))} /></Field>
        </div>}
      </div>
    </details>
    <p className="text-xs text-app-muted">{t('domains.test_users.saved_note')}</p>
    {save.error && <p role="alert" className="rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger">{save.error.message}</p>}
    <DialogFooter>
      <Button type="button" variant="ghost" onClick={onCancel}>{t('common:actions.cancel')}</Button>
      <Button type="submit" disabled={!ready || save.isPending}>{save.isPending && <LoaderCircle className="motion-safe:animate-spin" aria-hidden />}{t('domains.test_users.save')}</Button>
    </DialogFooter>
  </form>
}

function Field({ id, label, hint, children }: { id: string; label: string; hint?: string; children: React.ReactNode }) {
  return <div className="space-y-1.5">
    <label htmlFor={id} className="text-sm text-app-secondary">{label}</label>
    {children}
    {hint && <p id={`${id}-hint`} className="text-xs text-app-muted">{hint}</p>}
  </div>
}

// The domain's "Test users" tab: reusable accounts a scan signs in with, picked in the wizard instead of typing them again.
export function TestUsersPanel({ domain, admin }: { domain: Domain; admin: boolean }) {
  const { t } = useTranslation('sources')
  const confirm = useConfirm()
  const store = useStore(domain)
  const [editing, setEditing] = useState<Editing | null>(null)
  const [notice, setNotice] = useState('')
  const users = domain.test_users ?? []
  const remove = useMutation({
    mutationFn: (user: DomainTestUser) => apiPost('/api/domains/test-users', 'domain-test-users', { domain_id: domain.id, op: 'remove', id: user.id }),
    onSuccess: (saved, user) => { store(saved); setNotice(t('domains.test_users.removed', { name: user.name })) },
  })
  const ask = (user: DomainTestUser) => void confirm({
    title: t('domains.test_users.remove_title', { name: user.name }), description: t('domains.test_users.remove_text'),
    confirmLabel: t('domains.test_users.remove'), destructive: true,
  }).then(ok => { if (ok) { setNotice(''); remove.mutate(user) } })
  const add = (method: LoginMethod) => { setNotice(''); setEditing({ method, user: null }) }

  return <section aria-labelledby="domain-test-users" className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="space-y-1">
        <h2 id="domain-test-users" className="text-base font-semibold">{t('domains.test_users.title')}</h2>
        <p className="max-w-xl text-sm text-app-muted">{t('domains.test_users.text')}</p>
      </div>
      {admin && users.length > 0 && (users.length < TEST_USERS_MAX ? <AddTestUserMenu onPick={add} />
        : <p className="text-xs text-app-muted">{t('domains.test_users.limit', { max: TEST_USERS_MAX })}</p>)}
    </div>
    <div role="status">{notice && <p className="text-sm text-success">{notice}</p>}</div>
    {remove.isError && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{remove.error.message}</p>}
    {!admin ? <p className="text-sm text-app-muted">{domain.test_user_count ? t('domains.test_users.count', { count: domain.test_user_count }) : t('domains.test_users.empty')}</p>
    : users.length ? <ul aria-label={t('domains.test_users.list_label')} className="divide-y divide-app-line border-y border-app-line">{users.map(user => <li key={user.id} className="flex min-h-14 items-center gap-3 py-2 text-sm">
        <div className="min-w-0 flex-1 space-y-0.5">
          <p className="font-medium break-words">{user.name}</p>
          <p className="text-xs break-all text-app-muted">{testUserSummary(t, user, domain.host)}</p>
          {user.notes && <p className="text-xs break-words text-app-muted">{user.notes}</p>}
        </div>
        <span className="hidden text-xs text-app-muted sm:block">{user.last_used_at ? t('domains.test_users.last_used', { date: formatDay(user.last_used_at, { dateStyle: 'medium' }) }) : t('domains.test_users.never_used')}</span>
        <Menu><MenuTrigger render={<Button size="icon-sm" variant="ghost" aria-label={t('domains.test_users.actions_for', { name: user.name })} disabled={remove.isPending && remove.variables?.id === user.id} />}><MoreHorizontal /></MenuTrigger>
          <MenuContent>
            <MenuItem onClick={() => { setNotice(''); setEditing({ method: methodOf(user.method), user }) }}>{t('domains.test_users.edit')}</MenuItem>
            {user.method === 'password' && <MenuItem onClick={() => { setNotice(''); setEditing({ method: 'password_totp', user }) }}>{t('domains.test_users.add_totp')}</MenuItem>}
            <MenuItem className="text-danger" onClick={() => ask(user)}>{t('domains.test_users.remove')}</MenuItem>
          </MenuContent></Menu>
      </li>)}</ul>
    : <div className="flex flex-col items-center gap-3 py-12 text-center">
        <UserRound className="size-7 text-app-muted" aria-hidden />
        <p className="text-sm text-app-muted">{t('domains.test_users.empty')}</p>
        <AddTestUserMenu onPick={add} variant="brand" />
      </div>}
    {admin && <TestUserDialog domain={domain} editing={editing} onClose={() => setEditing(null)}
      onSaved={user => setNotice(t('domains.test_users.saved', { name: user.name }))} />}
  </section>
}
