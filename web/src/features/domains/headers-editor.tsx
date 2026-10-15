import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CircleNotchIcon, DotsThreeIcon, PlusIcon } from '@phosphor-icons/react'
import { apiPost } from '@/shared/api/client'
import { keys, type DomainHeader } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { useConfirm } from '@/shared/ui/confirm'
import { Input } from '@/shared/ui/input'
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import type { Domain } from '@/features/domains/domains'

const SUGGESTED = ['Authorization', 'Cookie', 'X-Api-Key', 'X-Auth-Token']
const MASK = '••••••'
type Page = { items: Domain[] }

// Request headers a domain's scans may send (an API key, a token, a session cookie). Saved encrypted on the server and
// never answered back: once saved, a value is only ever shown masked, and replacing it means typing a new one.
export function HeadersEditor({ domain, admin, adding, onAddingChange }: { domain: Domain; admin: boolean; adding: boolean; onAddingChange: (adding: boolean) => void }) {
  const { t } = useTranslation('sources')
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [replacing, setReplacing] = useState<string | null>(null)
  const [notice, setNotice] = useState('')
  const headers = domain.headers ?? []
  const change = useMutation({
    mutationFn: (body: { op: 'save' | 'remove'; name: string; value?: string }) => apiPost('/api/domains/headers', 'domain-headers', { domain_id: domain.id, ...body }),
    onSuccess: (result, body) => {
      // The answer carries the new list: show it at once, then refresh the rest of the row.
      queryClient.setQueryData<Page>(keys.domains, page => page && { ...page, items: page.items.map(item => item.id === domain.id ? { ...item, headers: result.headers, header_count: result.headers.length } : item) })
      void queryClient.invalidateQueries({ queryKey: keys.domains })
      setNotice(t(body.op === 'save' ? 'domains.access.saved' : 'domains.access.removed', { name: body.name }))
      setReplacing(null)
      onAddingChange(false)
    },
  })
  const remove = (header: DomainHeader) => void confirm({
    title: t('domains.access.remove_title', { name: header.name }), description: t('domains.access.confirm_remove'),
    confirmLabel: t('domains.access.remove'), destructive: true,
  }).then(ok => { if (ok) { setNotice(''); change.mutate({ op: 'remove', name: header.name }) } })
  const formOpen = adding || replacing !== null
  const close = () => { setReplacing(null); onAddingChange(false); change.reset() }

  if (!admin) return <p className="text-sm text-app-muted">{domain.header_count ? t('domains.access.count', { count: domain.header_count }) : t('domains.access.empty')}</p>
  return <div className="space-y-3">
    <div role="status">{notice && <p className="text-sm text-success">{notice}</p>}</div>
    {headers.length ? <ul aria-label={t('domains.access.list_label')} className="divide-y divide-app-line border-y border-app-line">{headers.map(header => <li key={header.name} className="flex min-h-11 items-center gap-3 py-1.5 text-sm">
        <span className="min-w-0 flex-1 font-mono break-all">{header.name}</span>
        <span className="font-mono text-app-muted"><span aria-hidden>{MASK}</span><span className="sr-only">{t('domains.access.masked')}</span></span>
        <Menu><MenuTrigger render={<Button size="icon-sm" variant="ghost" aria-label={t('domains.access.actions_for', { name: header.name })} />}><DotsThreeIcon /></MenuTrigger>
          <MenuContent><MenuItem onClick={() => { onAddingChange(false); setReplacing(header.name) }}>{t('domains.access.replace')}</MenuItem>
            <MenuItem className="text-danger" onClick={() => remove(header)}>{t('domains.access.remove')}</MenuItem></MenuContent></Menu>
      </li>)}</ul>
    : !formOpen && <p className="text-sm text-app-muted">{t('domains.access.empty')}</p>}
    {formOpen
      ? <HeaderForm key={replacing ?? 'new'} fixedName={replacing} busy={change.isPending} error={change.error?.message ?? ''} onCancel={close}
          onSave={(name, value) => { setNotice(''); change.mutate({ op: 'save', name, value }) }} />
      : headers.length < 10 && <Button variant="outline" size="sm" onClick={() => { setNotice(''); onAddingChange(true) }}><PlusIcon aria-hidden />{t('domains.access.add')}</Button>}
  </div>
}

// The page that proves the saved headers still sign in: without it, an expired cookie would look like a site with
// nothing behind its login, and the scan would mark those findings fixed. Admins only, once the domain has headers.
export function SessionCheck({ domain }: { domain: Domain }) {
  const { t } = useTranslation('sources')
  const id = useId()
  const field = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()
  const saved = domain.session_check ?? ''
  const [url, setUrl] = useState(saved)
  const [notice, setNotice] = useState('')
  const change = useMutation({
    mutationFn: (value: string) => apiPost('/api/domains/session-check', 'domain-session-check', { domain_id: domain.id, url: value }),
    onSuccess: result => {
      queryClient.setQueryData<Page>(keys.domains, page => page && { ...page, items: page.items.map(item => item.id === domain.id ? { ...item, session_check: result.session_check } : item) })
      void queryClient.invalidateQueries({ queryKey: keys.domains })
      setUrl(result.session_check ?? '')
      setNotice(t(result.session_check ? 'domains.access.check_saved' : 'domains.access.check_removed'))
      // Removing takes its button away: the focus goes back to the field rather than to the page.
      if (!result.session_check) field.current?.focus()
    },
  })
  const send = (value: string) => { setNotice(''); change.mutate(value) }
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); send(url.trim()) }
  const error = change.error?.message ?? ''
  if (!domain.headers?.length) return null
  // The server validates the address and says why in the panel's language: no browser bubble (noValidate).
  return <form onSubmit={submit} noValidate className="space-y-2 border-t border-app-line pt-4">
    <label htmlFor={`${id}-url`} className="block text-sm font-medium">{t('domains.access.check_label')}</label>
    <p id={`${id}-help`} className="max-w-2xl text-xs text-app-muted">{t('domains.access.check_help')}</p>
    <div className="flex flex-wrap items-center gap-2">
      <Input id={`${id}-url`} ref={field} type="url" inputMode="url" value={url} maxLength={2000} autoComplete="off" spellCheck={false}
        placeholder={t('domains.access.check_placeholder', { host: domain.host })} aria-describedby={`${id}-help${error ? ` ${id}-error` : ''}`}
        aria-invalid={error ? true : undefined} onChange={event => { setUrl(event.target.value); change.reset() }}
        className="min-w-0 flex-1 basis-64 border-input bg-card font-mono" />
      <Button type="submit" variant="outline" disabled={change.isPending || !url.trim() || url.trim() === saved}>
        {change.isPending && <CircleNotchIcon className="motion-safe:animate-spin" aria-hidden />}{t('domains.access.check_save')}</Button>
      {saved && <Button type="button" variant="ghost" disabled={change.isPending} onClick={() => send('')}>{t('domains.access.check_remove')}</Button>}
    </div>
    {error && <p id={`${id}-error`} role="alert" className="text-sm text-danger">{error}</p>}
    <div role="status">{notice && <p className="text-sm text-success">{notice}</p>}</div>
  </form>
}

function HeaderForm({ fixedName, busy, error, onCancel, onSave }: { fixedName: string | null; busy: boolean; error: string; onCancel: () => void; onSave: (name: string, value: string) => void }) {
  const { t } = useTranslation('sources')
  const [name, setName] = useState(fixedName ?? '')
  const [value, setValue] = useState('')
  const first = useRef<HTMLInputElement>(null)
  useEffect(() => { first.current?.focus() }, [])
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (name.trim() && value) onSave(name.trim(), value) }
  return <form onSubmit={submit} className="space-y-3">
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1"><label htmlFor="header-name" className="text-xs text-app-secondary">{t('domains.access.name')}</label>
        <Input id="header-name" ref={fixedName ? undefined : first} list="header-suggestions" value={name} readOnly={!!fixedName} required maxLength={64} autoComplete="off" spellCheck={false}
          onChange={event => setName(event.target.value)} className="border-input bg-card font-mono" />
        <datalist id="header-suggestions">{SUGGESTED.map(item => <option key={item} value={item} />)}</datalist></div>
      <div className="space-y-1"><label htmlFor="header-value" className="text-xs text-app-secondary">{t('domains.access.value')}</label>
        <Input id="header-value" ref={fixedName ? first : undefined} type="password" value={value} required maxLength={4096} autoComplete="new-password" spellCheck={false}
          onChange={event => setValue(event.target.value)} className="border-input bg-card font-mono" /></div>
    </div>
    <p className="text-xs text-app-muted">{t('domains.access.saved_note')}</p>
    {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    <div className="flex flex-wrap justify-end gap-2">
      <Button type="button" variant="ghost" size="sm" onClick={onCancel}>{t('common:actions.cancel')}</Button>
      <Button type="submit" size="sm" disabled={busy || !name.trim() || !value}>{busy && <CircleNotchIcon className="motion-safe:animate-spin" aria-hidden />}{t('domains.access.save')}</Button>
    </div>
  </form>
}
