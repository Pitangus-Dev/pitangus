import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { LoaderCircle, Plus, RefreshCw, X } from 'lucide-react'
import { apiPost, type PostBody } from '@/shared/api/client'
import { api } from '@/shared/api/http'
import { domainScopeQuery, keys, type DomainScope, type RelatedHost } from '@/shared/api/queries'
import { formatDay } from '@/shared/i18n/format'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { SkeletonList } from '@/shared/ui/loading'
import { useConfirm } from '@/shared/ui/confirm'
import { Segmented } from '@/shared/ui/segmented'
import { relatedEntry, type Domain } from '@/features/domains/domains'

type Change = Omit<PostBody<'/api/domains/scope'>, 'domain_id'>
type Placement = 'in_scope' | 'out_of_scope'
const FILTER_FROM = 8
const active = (status?: string) => status === 'queued' || status === 'running'

// The hosts related to a domain and the scope saved for it: the domain itself, always analyzed, then every host
// discovery found or someone added, each analyzed or excluded. Changes are saved on the domain at once, so the next
// scan (by hand or scheduled) starts from them. Only a DNS proof lets hosts in; otherwise they show, disabled, with why.
// `heading`: the level of its title where it sits (a page section, or inside a wizard step).
export function DomainScopeEditor({ domain, admin, autoSearch = false, onVerify, heading: Heading = 'h3' }: {
  domain: Domain; admin: boolean; autoSearch?: boolean; onVerify?: () => void; heading?: 'h2' | 'h3'
}) {
  const { t } = useTranslation('sources')
  const queryClient = useQueryClient()
  const confirm = useConfirm()
  const scope = useQuery(domainScopeQuery(domain.id))
  const [adding, setAdding] = useState(false)
  const [filter, setFilter] = useState('')
  // Where focus goes when the control that had it goes away (a removed row, Exclude all, the closed add form).
  const title = useRef<HTMLHeadingElement>(null)
  const addButton = useRef<HTMLButtonElement>(null)
  const refocus = useRef<'title' | 'add' | null>(null)
  const setRefocus = (target: 'title' | 'add') => { refocus.current = target }
  useEffect(() => {
    if (!refocus.current) return
    ;(refocus.current === 'add' ? addButton : title).current?.focus()
    refocus.current = null
  })
  const store = (result: DomainScope) => queryClient.setQueryData(keys.domainScope(domain.id), result)
  const change = useMutation({
    mutationFn: (body: Change) => apiPost('/api/domains/scope', 'domain-scope', { domain_id: domain.id, ...body }),
    onSuccess: (result, body) => {
      store(result)
      if (body.op === 'add') { setAdding(false); setRefocus('add') }
      if (body.op === 'remove' || body.op === 'exclude_all') setRefocus('title')
    },
    onError: () => void queryClient.invalidateQueries({ queryKey: keys.domainScope(domain.id) }),
  })
  const excludeAll = (count: number) => void confirm({
    title: t('domains.scope.exclude_all_title'), description: t('domains.scope.exclude_all_text', { count }), confirmLabel: t('domains.scope.exclude_all'),
  }).then(ok => { if (ok) change.mutate({ op: 'exclude_all' }) })
  const search = useMutation({
    mutationFn: () => api.post<DomainScope>('/api/domains/discover', 'discover-domain', { domain_id: domain.id }),
    onSuccess: store,
  })
  // Domains added before discovery existed (or while it was off) get their first search when someone opens the scope.
  const asked = useRef(false)
  useEffect(() => {
    const current = scope.data
    if (!autoSearch || !admin || asked.current || !current?.discovery.available || !current.covered || current.discovery.status !== 'idle') return
    asked.current = true
    search.mutate()
  }, [autoSearch, admin, scope.data, search])

  if (scope.isPending) return <SkeletonList rows={3} dense label={t('domains.scope.loading')} />
  if (scope.isError) return <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">
    {scope.error.message}<Button size="xs" variant="outline" onClick={() => void scope.refetch()}>{t('common:actions.retry')}</Button></div>

  const data = scope.data
  const { hosts, covered, discovery } = data
  const searching = active(discovery.status) || search.isPending
  const editable = admin && covered
  const pending = change.isPending && change.variables?.op === 'set' ? change.variables : null
  const placement = (item: RelatedHost): Placement => pending?.host === item.host && pending.state ? pending.state : item.state
  const needle = filter.trim().toLowerCase()
  const shown = needle ? hosts.filter(item => item.host.includes(needle)) : hosts
  const counts = discovery.counts
  const last = discovery.finished_at ? formatDay(discovery.finished_at, { dateStyle: 'medium' }) : ''

  return <div className="space-y-4">
    <ul className="divide-y divide-app-line rounded-xl border border-app-line">
      <li className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <span className="font-mono text-sm break-all">{domain.host}</span>
        <span className="text-xs text-app-muted">{t('domains.scope.root')}</span>
      </li>
    </ul>

    <section aria-labelledby={`related-${domain.id}`} className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Heading id={`related-${domain.id}`} ref={title} tabIndex={-1} className="text-sm font-semibold">{t('domains.scope.related', { count: hosts.length })}</Heading>
        <div className="flex flex-wrap items-center gap-1">
          {editable && data.in_scope > 0 && <Button variant="link" size="sm" className="text-app-secondary" disabled={change.isPending}
            onClick={() => excludeAll(data.in_scope)}>{t('domains.scope.exclude_all')}</Button>}
          {admin && discovery.available && <Button variant="ghost" size="sm" disabled={searching} onClick={() => search.mutate()}>
            <RefreshCw aria-hidden className={searching ? 'motion-safe:animate-spin' : undefined} />{t(discovery.status === 'idle' ? 'domains.scope.search' : 'domains.scope.search_again')}</Button>}
        </div>
      </div>

      <div role="status" className="text-xs">
        {searching ? <p className="flex items-center gap-2 text-app-secondary"><LoaderCircle className="size-3.5 motion-safe:animate-spin" aria-hidden />{t('domains.scope.searching')}</p>
          : !discovery.available ? <p className="text-app-muted">{discovery.unavailable}</p>
          : discovery.status === 'failed' ? <p className="text-warning">{discovery.note}</p>
          : discovery.status === 'done' && counts ? <p className="text-app-muted">{t('domains.scope.last_search', { date: last, kept: counts.kept, count: counts.found })}
            {counts.capped ? ` ${t('domains.scope.capped', { count: counts.capped, max: data.limit })}` : ''}</p>
          : null}
      </div>
      {!covered && data.reason && <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-warning-line bg-warning-soft px-4 py-3 text-sm text-warning">
        <span>{data.reason}</span>
        {admin && onVerify && <Button variant="outline" size="sm" onClick={onVerify}>{t('domains.page.verify_dns')}</Button>}
      </div>}
      {covered && !admin && <p className="text-xs text-app-muted">{t('domains.scope.admin_only')}</p>}

      {hosts.length > FILTER_FROM && <div className="space-y-1">
        <label htmlFor={`scope-filter-${domain.id}`} className="sr-only">{t('domains.scope.filter')}</label>
        <Input id={`scope-filter-${domain.id}`} type="search" value={filter} onChange={event => setFilter(event.target.value)} placeholder={t('domains.scope.filter')}
          autoComplete="off" spellCheck={false} className="border-app-line bg-app-soft font-mono sm:max-w-xs" />
      </div>}

      {hosts.length === 0 ? !searching && <p className="text-sm text-app-muted">{t(discovery.available ? 'domains.scope.empty' : 'domains.scope.empty_manual')}</p>
        : shown.length === 0 ? <p className="text-sm text-app-muted">{t('domains.scope.no_match')}</p>
        : <ul aria-label={t('domains.scope.list_label')} className="divide-y divide-app-line rounded-xl border border-app-line">{shown.map(item => <li key={item.host}
            className="flex flex-col gap-2 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between">
            <span className="min-w-0 space-y-0.5">
              <span className={`block font-mono text-sm break-all ${covered ? '' : 'text-app-muted'}`}>{item.host}</span>
              <span className="block text-xs text-app-muted">{item.origin === 'manual' ? t('domains.scope.manual')
                : item.last_seen ? t('domains.scope.seen', { date: formatDay(item.last_seen, { dateStyle: 'medium' }) }) : null}</span>
            </span>
            <span className="flex shrink-0 items-center gap-1">
              <Segmented label={t('domains.scope.row_label', { host: item.host })} value={placement(item)} disabled={!editable}
                options={[{ value: 'out_of_scope', label: t('domains.scope.out') }, { value: 'in_scope', label: t('domains.scope.in') }]}
                onChange={state => { if (!change.isPending) change.mutate({ op: 'set', host: item.host, state }) }} />
              {admin && item.origin === 'manual' && <Button variant="ghost" size="icon-sm" aria-label={t('domains.scope.remove', { host: item.host })} disabled={change.isPending}
                onClick={() => change.mutate({ op: 'remove', host: item.host })}><X /></Button>}
            </span>
          </li>)}</ul>}

      {editable && data.in_scope > 0 && <p className="text-xs text-app-muted">{t('domains.scope.count', { count: data.in_scope, max: data.scope_limit })}</p>}
      {change.error && !adding && <p role="alert" className="text-sm text-danger">{change.error.message}</p>}
      {search.error && <p role="alert" className="text-sm text-danger">{search.error.message}</p>}

      {editable && (adding
        ? <AddHostForm root={domain.host} busy={change.isPending} error={change.error?.message ?? ''} onCancel={() => { setAdding(false); change.reset(); setRefocus('add') }}
            onAdd={host => change.mutate({ op: 'add', host })} />
        : <Button ref={addButton} variant="outline" size="sm" onClick={() => { change.reset(); setAdding(true) }}><Plus aria-hidden />{t('domains.scope.add')}</Button>)}
      <p className="text-xs text-app-muted">{t('domains.scope.passive_note')}</p>
    </section>
  </div>
}

function AddHostForm({ root, busy, error, onCancel, onAdd }: { root: string; busy: boolean; error: string; onCancel: () => void; onAdd: (host: string) => void }) {
  const { t } = useTranslation('sources')
  const [draft, setDraft] = useState('')
  const [invalid, setInvalid] = useState('')
  const field = useRef<HTMLInputElement>(null)
  useEffect(() => { field.current?.focus() }, [])
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const entry = relatedEntry(draft, root)
    if ('error' in entry) {
      setInvalid(entry.error === 'foreign' ? t('domains.scope.foreign', { host: draft.trim(), domain: root })
        : entry.error === 'root' ? t('domains.scope.already_root') : t('domains.scope.invalid', { host: draft.trim() }))
      return
    }
    onAdd(entry.host)
  }
  const message = invalid || error
  return <form onSubmit={submit} className="space-y-1">
    <label htmlFor={`scope-add-${root}`} className="text-xs text-app-secondary">{t('domains.scope.add_label', { domain: root })}</label>
    <div className="flex flex-wrap gap-2">
      <Input id={`scope-add-${root}`} ref={field} value={draft} onChange={event => { setDraft(event.target.value); setInvalid('') }} placeholder={`app.${root}`}
        autoComplete="off" spellCheck={false} maxLength={253} aria-invalid={!!message || undefined} aria-describedby={`scope-add-error-${root}`}
        className="min-w-0 flex-1 border-app-line bg-app-soft font-mono" />
      <Button type="submit" disabled={busy || !draft.trim()}>{busy && <LoaderCircle className="motion-safe:animate-spin" aria-hidden />}{t('common:actions.add')}</Button>
      <Button type="button" variant="ghost" onClick={onCancel}>{t('common:actions.cancel')}</Button>
    </div>
    <p id={`scope-add-error-${root}`} role="alert" className="text-xs text-danger">{message}</p>
  </form>
}
