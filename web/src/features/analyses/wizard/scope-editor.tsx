import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, X } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Segmented, type SegmentOption } from '@/shared/ui/segmented'
import { SCOPE_MAX, scopeEntry, type ScopeHost } from '@/features/analyses/wizard/model'

type Placement = 'in' | 'out'

// The hosts a scan may reach: the domain itself, always, plus subdomains or wildcards added here (DNS proofs only).
// `options` stays a prop: when active tests exist, "In" splits into "Browse only" and "Test actively".
export function ScopeEditor({ root, hosts, onChange, options }: { root: string; hosts: ScopeHost[]; onChange: (hosts: ScopeHost[]) => void; options?: SegmentOption<Placement>[] }) {
  const { t } = useTranslation('analyses')
  const [draft, setDraft] = useState('')
  const [error, setError] = useState('')
  const choices = options ?? [{ value: 'out', label: t('scope.out') }, { value: 'in', label: t('scope.in') }]
  const add = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const entry = scopeEntry(draft, root)
    if ('error' in entry) { setError(entry.error === 'foreign' ? t('scope.foreign', { host: draft.trim(), domain: root }) : entry.error === 'root' ? t('scope.already_root') : t('scope.invalid', { host: draft.trim() })); return }
    if (hosts.some(item => item.host === entry.host)) { setDraft(''); setError(''); return }
    if (hosts.length >= SCOPE_MAX) { setError(t('scope.too_many', { max: SCOPE_MAX })); return }
    onChange([...hosts, { host: entry.host, included: true }])
    setDraft(''); setError('')
  }
  return <div className="space-y-3 rounded-xl border border-app-line p-4">
    <ul className="divide-y divide-app-line">
      <li className="flex flex-col gap-1 py-2 sm:flex-row sm:items-center sm:justify-between"><span className="font-mono text-sm break-all">{root}</span><span className="text-xs text-app-muted">{t('scope.root')}</span></li>
      {hosts.map(item => <li key={item.host} className="flex flex-col gap-2 py-2 sm:flex-row sm:items-center sm:justify-between">
        <span className="font-mono text-sm break-all">{item.host}</span>
        <span className="flex items-center gap-1">
          <Segmented label={t('scope.row_label', { host: item.host })} value={item.included ? 'in' : 'out'} options={choices}
            onChange={next => onChange(hosts.map(entry => entry.host === item.host ? { ...entry, included: next === 'in' } : entry))} />
          <Button variant="ghost" size="icon-sm" aria-label={t('scope.remove', { host: item.host })} onClick={() => onChange(hosts.filter(entry => entry.host !== item.host))}><X /></Button>
        </span>
      </li>)}
    </ul>
    <form onSubmit={add} className="space-y-1">
      <label htmlFor="scope-add" className="text-xs text-app-secondary">{t('scope.add_label')}</label>
      <div className="flex gap-2"><Input id="scope-add" value={draft} onChange={event => { setDraft(event.target.value); setError('') }} placeholder={`*.staging.${root}`} autoComplete="off" spellCheck={false}
        aria-invalid={!!error || undefined} aria-describedby="scope-add-error" className="border-app-line bg-app-soft font-mono" />
        <Button type="submit" variant="outline" disabled={!draft.trim()}><Plus aria-hidden />{t('scope.add')}</Button></div>
      <p id="scope-add-error" role="status" className="text-xs text-danger">{error}</p>
    </form>
  </div>
}
