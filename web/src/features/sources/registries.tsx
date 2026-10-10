import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { LoaderCircle, Plus } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { api } from '@/shared/api/http'
import { formatDate } from '@/shared/lib/types'
import { SkeletonList } from '@/shared/ui/loading'
import { SettingsRow, SettingsRows, SettingsSection } from '@/shared/ui/settings-list'

type Registry = { registry: string; username: string; last4: string; saved_at: string | null; saved_by: string | null }

const HINTS = [
  ['registries.hints.ghcr.host', 'registries.hints.ghcr.user', 'registries.hints.ghcr.token'],
  ['registries.hints.docker.host', 'registries.hints.docker.user', 'registries.hints.docker.token'],
  ['registries.hints.ecr.host', 'registries.hints.ecr.user', 'registries.hints.ecr.token'],
  ['registries.hints.gar.host', 'registries.hints.gar.user', 'registries.hints.gar.token'],
] as const

// Read-only credentials for scanning images from private registries. Stored encrypted; they never come back.
export function Registries({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation('sources')
  const [rows, setRows] = useState<Registry[] | null>(null)
  const [allowPrivate, setAllowPrivate] = useState(false)
  const [registry, setRegistry] = useState('')
  const [username, setUsername] = useState('')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState('')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => { api.get<{ registries: Registry[]; allow_private: boolean }>('/api/registries').then(data => { setRows(data.registries); setAllowPrivate(data.allow_private) }).catch(caught => setError(String(caught))) }, [])

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('save'); setError('')
    try {
      const data = await api.post<{ registries: Registry[] }>('/api/registries', 'save-registry', { action: 'save', registry: registry.trim(), username: username.trim(), token })
      setRows(data.registries); setRegistry(''); setUsername(''); setToken(''); setAdding(false)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const remove = async (host: string) => {
    setBusy(host); setError('')
    try { setRows((await api.post<{ registries: Registry[] }>('/api/registries', 'save-registry', { action: 'remove', registry: host })).registries) }
    catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy('') }
  }
  const saved = (row: Registry) => row.saved_at && row.saved_by ? t('registries.saved_on_by', { date: formatDate(row.saved_at), name: row.saved_by })
    : row.saved_at ? formatDate(row.saved_at) : row.saved_by ? t('registries.saved_by', { name: row.saved_by }) : null

  const formId = 'registry-form'
  const firstField = useRef<HTMLInputElement>(null)
  return <SettingsSection id="integrations-registries" title={t('registries.title')}
    description={<Trans t={t} i18nKey="registries.description" components={{ b: <strong className="font-medium" /> }} />}
    action={canManage && <Button size="sm" variant="outline" aria-expanded={adding} aria-controls={formId} onClick={() => { setAdding(!adding); if (!adding) window.setTimeout(() => firstField.current?.focus(), 0) }}><Plus />{t('registries.add')}</Button>}>
    {!rows && !error && <SkeletonList rows={2} dense label={t('registries.loading')} />}
    {rows && <SettingsRows>
      {rows.map(row => <SettingsRow key={row.registry} title={<span className="font-mono">{row.registry}</span>} status={t('registries.row.saved')} tone="success"
        meta={[row.username, t('registries.token_last4', { last4: row.last4 }), saved(row)].filter(Boolean).join(' · ')}
        actions={canManage && <Button variant="ghost" size="sm" aria-label={t('registries.remove_label', { host: row.registry })} disabled={!!busy} onClick={() => void remove(row.registry)}>{busy === row.registry && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.remove')}</Button>} />)}
      {rows.length === 0 && <SettingsRow empty title={t('registries.row.none')} meta={canManage ? t('registries.empty') : t('registries.admin_only')} />}
    </SettingsRows>}
    {canManage && <div id={formId} hidden={!adding} className="space-y-3 rounded-lg border border-app-line p-4">
      <form onSubmit={save} className="grid gap-3 md:grid-cols-3">
        <div className="space-y-1.5"><label htmlFor="registry-host" className="text-xs text-app-muted">{t('registries.host')}</label><Input ref={firstField} id="registry-host" required value={registry} onChange={event => setRegistry(event.target.value)} maxLength={200} placeholder="ghcr.io" className="border-app-line bg-app-soft font-mono" /></div>
        <div className="space-y-1.5"><label htmlFor="registry-user" className="text-xs text-app-muted">{t('registries.username')}</label><Input id="registry-user" required value={username} onChange={event => setUsername(event.target.value)} maxLength={200} autoComplete="off" className="border-app-line bg-app-soft" /></div>
        <div className="space-y-1.5"><label htmlFor="registry-token" className="text-xs text-app-muted">{t('registries.token')}</label><Input id="registry-token" required type="password" autoComplete="new-password" value={token} onChange={event => setToken(event.target.value)} minLength={8} maxLength={4096} className="border-app-line bg-app-soft" /></div>
        <div className="flex flex-wrap items-center gap-3 md:col-span-3"><Button type="submit" disabled={!!busy}>{busy === 'save' && <LoaderCircle className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
          <Button type="button" variant="ghost" onClick={() => setAdding(false)}>{t('common:actions.cancel')}</Button>
          <span className="text-xs text-app-subtle">{t('registries.stored_note')}</span></div>
      </form>
      <details className="text-xs text-app-muted"><summary className="min-h-6 cursor-pointer">{t('registries.help')}</summary>
        <table className="mt-2 w-full text-left"><thead><tr className="text-app-subtle"><th scope="col" className="py-1.5 pr-3 font-medium">{t('registries.columns.registry')}</th><th scope="col" className="py-1.5 pr-3 font-medium">{t('registries.columns.username')}</th><th scope="col" className="py-1.5 font-medium">{t('registries.columns.token')}</th></tr></thead><tbody>{HINTS.map(([host, user, secret]) => <tr key={host} className="border-t border-app-line"><td className="py-1.5 pr-3 font-mono">{t(host)}</td><td className="py-1.5 pr-3">{t(user)}</td><td className="py-1.5">{t(secret)}</td></tr>)}</tbody></table>
        {!allowPrivate && <p className="mt-2"><Trans t={t} i18nKey="registries.private_blocked" components={{ code: <span className="font-mono" /> }} /></p>}
      </details>
    </div>}
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
  </SettingsSection>
}
