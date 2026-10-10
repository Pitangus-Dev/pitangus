import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { LoaderCircle, Plus } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { useConfirm } from '@/shared/ui/confirm'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { intlLocale } from '@/shared/i18n'
import { formatDate } from '@/shared/lib/types'
import { SkeletonList } from '@/shared/ui/loading'
import { SettingsRow, SettingsRows, SettingsSection } from '@/shared/ui/settings-list'
import { CodeBlock } from '@/features/findings/fix-guide'
import { SelectField } from '@/shared/ui/select-field'

type Kind = 'slack' | 'teams' | 'webhook'
type Channel = { id: string; kind: Kind; name: string; host: string; events: string[]; threshold: string; signed: boolean
  created_by?: string; created_at?: string; last?: { at: string; ok: boolean; detail: string } | null }
type Listing = { channels: Channel[]; kinds: Record<Kind, string>; events: Record<string, string>; thresholds: string[]; links: boolean }

const THRESHOLD: Record<string, string> = { critical: 'notifications.threshold.critical', high: 'notifications.threshold.high', medium: 'notifications.threshold.medium' }
const HINT = { slack: 'notifications.hint.slack', teams: 'notifications.hint.teams', webhook: 'notifications.hint.webhook' } as const

// Messages to Slack, Teams or a webhook when something that matters shows up, without opening the panel.
export function Notifications() {
  const { t } = useTranslation('integrations')
  const confirm = useConfirm()
  const [data, setData] = useState<Listing | null>(null)
  const [adding, setAdding] = useState(false)
  const [kind, setKind] = useState<Kind>('slack')
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [events, setEvents] = useState<string[]>(['findings'])
  const [threshold, setThreshold] = useState('high')
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [secret, setSecret] = useState<string | null>(null)
  useEffect(() => { api.get<Listing>('/api/notifications').then(setData).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [])
  const thresholdLabel = (value: string) => THRESHOLD[value] ? t(THRESHOLD[value]) : value

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('save'); setError(''); setNotice('')
    try {
      const result = await api.post<{ channel: Channel; secret: string | null }>('/api/notifications', 'notifications', { op: 'save', kind, name: name.trim(), url: url.trim(), events, threshold })
      setData(previous => previous ? { ...previous, channels: [...previous.channels, result.channel] } : previous)
      setSecret(result.secret); setName(''); setUrl(''); setAdding(false)
      setNotice(t('notifications.saved', { name: result.channel.name }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const act = async (op: 'remove' | 'test', channel: Channel) => {
    // The URL never comes back to the browser: removing a channel means asking Slack or Teams for it again.
    if (op === 'remove' && !await confirm({ title: t('notifications.remove_title', { name: channel.name }), description: t('notifications.confirm_remove'), confirmLabel: t('notifications.remove_channel'), destructive: true })) return
    setBusy(`${op}:${channel.id}`); setError(''); setNotice('')
    try {
      const result = await api.post<{ channels: Channel[]; ok?: boolean; detail?: string }>('/api/notifications', 'notifications', { op, id: channel.id })
      setData(previous => previous ? { ...previous, channels: result.channels } : previous)
      if (op === 'test' && result.ok) setNotice(t('notifications.test_ok', { name: channel.name, detail: result.detail ?? '' }))
      if (op === 'test' && !result.ok) setError(t('notifications.test_failed', { name: channel.name, detail: result.detail ?? '' }))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }

  const list = (items: string[]) => new Intl.ListFormat(intlLocale(), { type: 'conjunction' }).format(items).toLowerCase()
  const formId = 'notification-form'
  const firstField = useRef<HTMLInputElement>(null)
  return <SettingsSection id="integrations-notifications" title={t('notifications.title')} description={t('notifications.description')}
    action={data && <Button size="sm" variant="outline" aria-expanded={adding} aria-controls={formId} onClick={() => { setAdding(!adding); if (!adding) window.setTimeout(() => firstField.current?.focus(), 0) }}><Plus />{t('notifications.add')}</Button>}>
    {!data && !error && <SkeletonList rows={2} dense label={t('notifications.loading')} />}
    {data && <SettingsRows>
      {data.channels.map(channel => <SettingsRow key={channel.id} title={channel.name}
        status={channel.last ? channel.last.ok ? t('notifications.last_ok', { date: formatDate(channel.last.at) }) : t('notifications.last_failed', { date: formatDate(channel.last.at), detail: channel.last.detail }) : t('notifications.row.active')}
        tone={channel.last && !channel.last.ok ? 'danger' : 'success'}
        meta={[data.kinds[channel.kind], channel.host, list(channel.events.map(item => data.events[item] ?? item)), thresholdLabel(channel.threshold).toLowerCase(), channel.signed ? t('notifications.signed') : ''].filter(Boolean).join(' · ')}
        actions={<>
          <Button variant="ghost" size="sm" aria-label={t('notifications.test_label', { name: channel.name })} disabled={!!busy} onClick={() => void act('test', channel)}>{busy === `test:${channel.id}` && <LoaderCircle className="motion-safe:animate-spin" />}{t('notifications.test')}</Button>
          <Button variant="ghost" size="sm" aria-label={t('notifications.remove_label', { name: channel.name })} disabled={!!busy} onClick={() => void act('remove', channel)}>{busy === `remove:${channel.id}` && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.remove')}</Button></>} />)}
      {data.channels.length === 0 && <SettingsRow empty title={t('notifications.row.none')} meta={t('notifications.row.none_hint')} />}
    </SettingsRows>}
    {secret && <div className="space-y-2 rounded-lg border border-warning-line bg-warning-soft p-3 text-xs text-warning">
      <p className="font-medium">{t('notifications.secret_title')}</p>
      <CodeBlock code={secret} label={t('notifications.secret_label')} />
      <p>{t('notifications.secret_help')}</p>
      <Button size="sm" variant="ghost" onClick={() => setSecret(null)}>{t('notifications.secret_saved')}</Button></div>}
    {data && <form id={formId} hidden={!adding} onSubmit={save} className="space-y-4 rounded-lg border border-app-line p-4">
      <fieldset className="space-y-2"><legend className="text-xs text-app-muted">{t('notifications.where')}</legend>
        <div className="grid gap-2 sm:grid-cols-3">{(Object.keys(data.kinds) as Kind[]).map(item => <label key={item} className={`flex min-h-9 cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm ${kind === item ? 'border-app-fg bg-app-soft' : 'border-app-line'}`}>
          <input type="radio" name="notify-kind" value={item} checked={kind === item} onChange={() => setKind(item)} className="size-4 accent-brand" />{data.kinds[item]}</label>)}</div>
        <p className="text-xs text-app-subtle">{t(HINT[kind])}</p></fieldset>
      <div className="grid gap-3 md:grid-cols-2">
        <div className="space-y-1.5"><label htmlFor="notify-name" className="text-xs text-app-muted">{t('notifications.name')}</label><Input ref={firstField} id="notify-name" required maxLength={60} value={name} onChange={event => setName(event.target.value)} placeholder={t('notifications.name_placeholder')} className="border-app-line bg-app-soft" /></div>
        <div className="space-y-1.5"><label htmlFor="notify-url" className="text-xs text-app-muted">{t('notifications.url')}</label><Input id="notify-url" required type="password" autoComplete="off" maxLength={2048} value={url} onChange={event => setUrl(event.target.value)} placeholder="https://…" className="border-app-line bg-app-soft font-mono" /></div>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <fieldset className="space-y-1.5"><legend className="text-xs text-app-muted">{t('notifications.events')}</legend>{Object.entries(data.events).map(([id, label]) => <label key={id} className="flex min-h-6 items-center gap-2 text-sm">
          <input type="checkbox" checked={events.includes(id)} onChange={event => setEvents(previous => event.target.checked ? [...previous, id] : previous.filter(item => item !== id))} className="size-4 accent-brand" />{label}</label>)}</fieldset>
        <div className="space-y-1.5"><label htmlFor="notify-threshold" className="text-xs text-app-muted">{t('notifications.threshold_label')}</label>
          <SelectField id="notify-threshold" value={threshold} disabled={!events.includes('findings')} onValueChange={setThreshold} options={data.thresholds.map(item => ({ value: item, label: thresholdLabel(item) }))} /></div>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={!!busy || !events.length}>{busy === 'save' && <LoaderCircle className="motion-safe:animate-spin" />}{t('notifications.save')}</Button>
        <Button type="button" variant="ghost" onClick={() => setAdding(false)}>{t('common:actions.cancel')}</Button>
        <span className="text-xs text-app-subtle">{t('notifications.url_note')}</span>
      </div>
      {!data.links && <p className="text-xs text-app-subtle">{t('notifications.links_note')}</p>}
    </form>}
    {/* Live regions stay mounted so the text is announced when it changes. */}
    <p role="status" className="text-xs text-app-muted empty:hidden">{notice}</p>
    <div role="alert" className={error ? 'rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger' : 'hidden'}>{error}</div>
  </SettingsSection>
}
