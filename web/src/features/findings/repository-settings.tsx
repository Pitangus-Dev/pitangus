import { useId, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { CircleNotchIcon, EyeIcon, FolderMinusIcon, type Icon, KeyIcon, PencilSimpleIcon, PlusIcon } from '@phosphor-icons/react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { Bone } from '@/shared/ui/loading'
import { ApiError, api } from '@/shared/api/http'
import { apiPost, type PostResponse } from '@/shared/api/client'
import { assetSecretsQuery, exclusionsPreviewQuery, exclusionsQuery, invalidateFindings, keys, type Exclusions } from '@/shared/api/queries'
import { SecretRulesDialog } from '@/features/findings/secret-rules'
import { entryCount, secretCounts, secretSummary } from '@/features/findings/secret-summary'
import { formatDate } from '@/shared/lib/types'
import { useDebounced } from '@/shared/lib/useDebounced'

type Saved = Exclusions & { moved: { excluded: number; reopened: number } }
const SHOWN = 2
// The server's limits (findings/exclusions.py): patterns, and the shortest reason it keeps in the history.
const MAX_PATTERNS = 50
const REASON_MIN = 5
const lines = (value: string) => value.split('\n').map(line => line.trim()).filter(Boolean)

// A repository's own settings in one strip, each said in plain words: excluded paths (listed apart, never hidden) and
// its secret detection entries (on top of the organization's). Deadlines are global: only a link to the policy.
export function RepositorySettings({ assetKey, name, kind, canEdit, onOpenPolicies }: {
  assetKey: string; name: string; kind: 'repository' | 'image'; canEdit: boolean; onOpenPolicies: () => void
}) {
  const secrets = kind === 'repository'
  const { t } = useTranslation('findings')
  const id = useId()
  const [notice, setNotice] = useState('')
  // Same queries as the entries below (shared cache): only to announce the loading once.
  const pathsPending = useQuery(exclusionsQuery(assetKey)).isPending
  const secretsPending = useQuery({ ...assetSecretsQuery(assetKey), enabled: secrets }).isPending
  const loading = pathsPending || (secrets && secretsPending)
  return <section aria-labelledby={id} className="rounded-xl border border-app-line bg-inset px-4 py-3 text-sm">
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
      <h2 id={id} className="text-xs font-medium text-app-subtle">{kind === 'image' ? t('repo_settings.title_image') : t('repo_settings.title')}</h2>
      <Button size="xs" variant="link" className="h-auto min-h-6 px-0 text-app-muted" onClick={onOpenPolicies}>{t('repo_settings.deadlines')}</Button>
    </div>
    <div className="mt-1 divide-y divide-app-line">
      <ExcludedPaths assetKey={assetKey} name={name} kind={kind} canEdit={canEdit} onSaved={setNotice} />
      {secrets && <RepositorySecrets assetKey={assetKey} name={name} canEdit={canEdit} onSaved={setNotice} onOpenPolicies={onOpenPolicies} />}
    </div>
    <p role="status" className="mt-1 text-xs text-success empty:hidden">{notice}</p>
    {loading && <span role="status" className="sr-only">{t('common:state.loading')}</span>}
  </section>
}

// Loading: a bone the size of the summary (the strip announces it once). Error: said, with a retry.
function Status({ query }: { query: { isError: boolean; refetch: () => unknown } }) {
  const { t } = useTranslation('findings')
  if (!query.isError) return <Bone className="h-4 w-24" />
  return <span role="alert" className="flex items-center gap-2 text-danger">{t('repo_settings.load_failed')}
    <Button size="xs" variant="outline" onClick={() => void query.refetch()}>{t('common:actions.retry')}</Button></span>
}

// One setting: what it is, where it stands and what it is for, in plain words, with its action on the right.
function Setting({ icon: Icon, label, hint, children, action }: { icon: Icon; label: string; hint: string; children: ReactNode; action: ReactNode }) {
  return <div className="grid grid-cols-[16px_minmax(0,1fr)] items-start gap-x-2 py-2 md:grid-cols-[16px_minmax(0,1fr)_auto] md:items-center">
    <Icon aria-hidden className="mt-0.5 size-4 shrink-0 text-app-subtle md:mt-0" />
    <div className="min-w-0">
      <p className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1"><span className="font-medium text-app-secondary">{label}</span>
        <span className="flex min-w-0 flex-wrap items-center gap-1 text-app-muted">{children}</span></p>
      <p className="text-xs leading-5 text-app-subtle">{hint}</p>
    </div>
    {action && <div className="col-start-2 mt-1.5 md:col-start-3 md:mt-0">{action}</div>}
  </div>
}

// A pattern as people read it: the path in mono and, when it is limited to one rule, that rule after it.
function Pattern({ value }: { value: string }) {
  const { t } = useTranslation('findings')
  const [path, rule] = value.split(' ')
  const chip = 'rounded-sm border border-app-line bg-app px-1.5 py-0.5 font-mono text-xs break-all'
  return <span className="inline-flex flex-wrap items-center gap-1"><code className={chip}>{path}</code>
    {rule && <span className="text-xs"><Trans t={t} i18nKey="exclusions.only_rule" values={{ rule }} components={{ code: <code className={chip} /> }} /></span>}</span>
}

function ExcludedPaths({ assetKey, name, kind, canEdit, onSaved }: { assetKey: string; name: string; kind: 'repository' | 'image'; canEdit: boolean; onSaved: (notice: string) => void }) {
  const { t } = useTranslation('findings')
  const query = useQuery(exclusionsQuery(assetKey))
  const state = query.data
  const [open, setOpen] = useState(false)
  const patterns = state?.patterns ?? []
  const summary = !state ? <Status query={query} />
    : patterns.length ? <>{patterns.slice(0, SHOWN).map(item => <Pattern key={item} value={item} />)}
      {patterns.length > SHOWN && <span className="text-xs">{t('repo_settings.more', { count: patterns.length - SHOWN })}</span>}</>
    : t('repo_settings.none')
  const action = state && (canEdit ? <Button size="xs" variant="outline" onClick={() => setOpen(true)}>{patterns.length ? <><PencilSimpleIcon />{t('common:actions.edit')}</> : <><FolderMinusIcon />{t('repo_settings.exclude')}</>}</Button>
    : patterns.length > SHOWN && <Button size="xs" variant="outline" onClick={() => setOpen(true)}><EyeIcon />{t('repo_settings.view')}</Button>)
  return <>
    <Setting icon={FolderMinusIcon} label={t('repo_settings.paths')} hint={kind === 'image' ? t('repo_settings.paths_hint_image') : t('repo_settings.paths_hint')} action={action}>{summary}</Setting>
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t('exclusions.title_for', { name })}</DialogTitle>
          <DialogDescription>{kind === 'image' ? t('exclusions.dialog_help_image') : t('exclusions.dialog_help')}</DialogDescription>
        </DialogHeader>
        {state?.by && <p className="text-xs text-app-subtle">{t('exclusions.last_change', { reason: state.reason ?? '—', by: state.by, date: state.at ? formatDate(state.at) : '—' })}</p>}
        {/* Mounted only while open: the form and its preview start from what is saved, never from an earlier edit. */}
        {open && state && (canEdit
          ? <ExclusionsForm assetKey={assetKey} kind={kind} initial={state} onCancel={() => setOpen(false)} onSaved={notice => { setOpen(false); onSaved(notice) }} />
          : <p className="flex flex-wrap gap-1.5">{patterns.map(item => <Pattern key={item} value={item} />)}</p>)}
      </DialogContent>
    </Dialog>
  </>
}

// What people usually exclude, each with what it means; choosing one adds its line (an example is easier to adapt than
// a syntax to learn). The last one is a known false positive: one rule in one place.
const EXAMPLES = [
  { pattern: 'tests/fixtures/**', meaning: 'exclusions.examples.folder' },
  { pattern: '**/testdata', meaning: 'exclusions.examples.anywhere' },
  { pattern: 'docs/*.md', meaning: 'exclusions.examples.files' },
  { pattern: 'tests/** generic-api-key', meaning: 'exclusions.examples.rule' },
] as const

function Examples({ typed, onAdd }: { typed: string[]; onAdd: (pattern: string) => void }) {
  const { t } = useTranslation('findings')
  const id = useId()
  return <section aria-labelledby={id} className="space-y-1">
    <h3 id={id} className="text-xs font-medium text-app-muted">{t('exclusions.examples.title')}</h3>
    <ul className="divide-y divide-app-line rounded-xl border border-app-line">{EXAMPLES.map(example => {
      const [path, rule] = example.pattern.split(' ')
      const added = typed.includes(example.pattern)
      return <li key={example.pattern} className="flex items-center justify-between gap-3 px-3 py-2">
        <span className="min-w-0"><code className="font-mono text-xs break-all text-app-fg">{example.pattern}</code>
          <span className="block text-xs leading-5 text-app-muted">{t(example.meaning, { path, rule })}</span></span>
        <Button type="button" size="xs" variant="ghost" disabled={added} aria-label={added ? t('exclusions.examples.added_named', { pattern: example.pattern }) : t('exclusions.examples.add_named', { pattern: example.pattern })} onClick={() => onAdd(example.pattern)}>
          {added ? t('exclusions.examples.added') : <><PlusIcon />{t('exclusions.examples.add')}</>}</Button>
      </li>
    })}</ul>
  </section>
}

function ExclusionsForm({ assetKey, kind, initial, onSaved, onCancel }: { assetKey: string; kind: 'repository' | 'image'; initial: Exclusions; onSaved: (notice: string) => void; onCancel: () => void }) {
  const { t } = useTranslation('findings')
  const id = useId()
  const queryClient = useQueryClient()
  const [text, setText] = useState(initial.patterns.join('\n'))
  const [reason, setReason] = useState(initial.reason ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const typed = useMemo(() => lines(text), [text])
  // While the paths are typed: what saving them would move now, checked as saving checks them.
  const settled = useDebounced(typed, 400)
  const preview = useQuery(exclusionsPreviewQuery(assetKey, settled))
  const waiting = settled.join('\n') !== typed.join('\n') || preview.isPlaceholderData
  const refused = preview.error instanceof ApiError && preview.error.status === 400
  const reasonMissing = typed.length > 0 && reason.trim().length < REASON_MIN

  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (reasonMissing) { setError(t('exclusions.reason_needed', { min: REASON_MIN })); document.getElementById(`${id}-reason`)?.focus(); return }
    setBusy(true); setError('')
    try {
      const saved = await api.post<Saved>('/api/assets/exclusions', 'save-exclusions', { key: assetKey, patterns: typed, reason: reason.trim() })
      queryClient.setQueryData(keys.exclusions(assetKey), saved)
      // Saving moves findings in and out of Excluded.
      void invalidateFindings(queryClient)
      const excluded = saved.moved.excluded ? t('exclusions.moved_excluded', { count: saved.moved.excluded }) : ''
      const reopened = saved.moved.reopened ? t('exclusions.moved_reopened', { count: saved.moved.reopened }) : ''
      onSaved(excluded && reopened ? t('exclusions.moved_both', { excluded, reopened }) : excluded || reopened || t('exclusions.saved'))
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) } finally { setBusy(false) }
  }

  const add = (pattern: string) => setText(current => [...lines(current), pattern].join('\n'))
  return <form onSubmit={save} className="space-y-4" noValidate>
    {kind === 'repository' && <Examples typed={typed} onAdd={add} />}
    <div className="space-y-1">
      <label className="block text-xs font-medium text-app-muted" htmlFor={`${id}-patterns`}>{t('exclusions.label')}</label>
      <p id={`${id}-help`} className="text-xs leading-5 text-app-muted"><Trans t={t} i18nKey={kind === 'image' ? 'exclusions.patterns_help_image' : 'exclusions.patterns_help'} values={{ max: MAX_PATTERNS }} components={{ code: <code className="font-mono" /> }} /></p>
      <textarea id={`${id}-patterns`} value={text} onChange={event => setText(event.target.value)} rows={4} spellCheck={false}
        aria-describedby={`${id}-help ${id}-preview`} aria-invalid={refused || undefined}
        className="w-full rounded-lg border border-input bg-card px-3 py-2 font-mono text-xs text-app-fg aria-invalid:border-danger" />
    </div>
    <ExclusionPreview id={`${id}-preview`} preview={preview} waiting={waiting} />
    <div className="space-y-1">
      <label htmlFor={`${id}-reason`} className="text-xs font-medium text-app-muted">{typed.length ? t('exclusions.reason_required') : t('exclusions.reason')}</label>
      <Input id={`${id}-reason`} value={reason} onChange={event => setReason(event.target.value)} maxLength={300} placeholder={t('exclusions.reason_placeholder')}
        aria-required={typed.length > 0 || undefined} aria-invalid={(!!error && reasonMissing) || undefined}
        aria-describedby={error ? `${id}-error` : undefined} className="h-9 border-input bg-card" />
    </div>
    {error && <p id={`${id}-error`} role="alert" className="text-xs text-danger">{error}</p>}
    <DialogFooter>
      <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>{t('common:actions.cancel')}</Button>
      <Button type="submit" disabled={busy}>{busy && <CircleNotchIcon className="motion-safe:animate-spin" />}{t('common:actions.save')}</Button>
    </DialogFooter>
  </form>
}

// What saving the typed paths would move now, with the first of their paths: before saving, not after. `waiting`: the
// answer shown is for an earlier text.
function ExclusionPreview({ id, preview, waiting }: { id: string; preview: UseQueryResult<PostResponse<'/api/assets/exclusions/preview'>>; waiting: boolean }) {
  const { t } = useTranslation('findings')
  const data = preview.data
  const paths = (items: string[], total: number) => items.length > 0 && <span className="mt-0.5 flex flex-wrap items-center gap-1">
    {items.map(path => <code key={path} className="rounded-sm border border-app-line bg-app px-1.5 py-0.5 font-mono break-all">{path}</code>)}
    {total > items.length && <span>{t('repo_settings.more', { count: total - items.length })}</span>}</span>
  return <div className="space-y-1 text-xs text-app-muted"><p className="font-medium text-app-secondary">{t('exclusions.preview.title')}</p>
    <div id={id} role="status" className="space-y-1">
    {preview.isError ? <p className="text-danger">{preview.error.message}</p>
      : !data || waiting ? <p>{t('exclusions.preview.checking')}</p>
      : !data.excluded && !data.reopened ? <p>{t('exclusions.preview.nothing')}</p>
      : <>
        {data.excluded > 0 && <p>{t('exclusions.preview.excluded', { count: data.excluded })}{paths(data.excluded_paths, data.excluded_path_count)}</p>}
        {data.reopened > 0 && <p>{t('exclusions.preview.reopened', { count: data.reopened })}{paths(data.reopened_paths, data.reopened_path_count)}</p>}
      </>}
  </div></div>
}

function RepositorySecrets({ assetKey, name, canEdit, onSaved, onOpenPolicies }: {
  assetKey: string; name: string; canEdit: boolean; onSaved: (notice: string) => void; onOpenPolicies: () => void
}) {
  const { t } = useTranslation('findings')
  const queryClient = useQueryClient()
  const query = useQuery(assetSecretsQuery(assetKey))
  const config = query.data
  const [open, setOpen] = useState(false)
  const own = config ? entryCount(secretCounts(config)) : 0
  const summary = !config ? <Status query={query} />
    : own ? t('repo_settings.secrets_custom', { count: own }) : t('repo_settings.secrets_defaults')
  const action = config && <Button size="xs" variant="outline" onClick={() => setOpen(true)}>
    {canEdit ? <><PencilSimpleIcon />{own ? t('common:actions.edit') : t('repo_settings.customize')}</> : <><EyeIcon />{t('repo_settings.view')}</>}</Button>
  return <>
    <Setting icon={KeyIcon} label={t('repo_settings.secrets')} hint={t('repo_settings.secrets_hint')} action={action}>{summary}</Setting>
    {config && <SecretRulesDialog open={open} onOpenChange={setOpen} title={t('repo_settings.secrets_title', { name })} description={t('repo_settings.secrets_help')}
      config={config} canEdit={canEdit} save={body => apiPost('/api/assets/secrets', 'save-asset-secret-rules', { ...body, key: assetKey })}
      onSaved={saved => { queryClient.setQueryData(keys.assetSecrets(assetKey), saved); setOpen(false); onSaved(t('secret_rules.saved')) }}>
      <p className="flex flex-wrap items-center gap-x-2 text-xs text-app-subtle">{entryCount(config.defaults) ? t('repo_settings.defaults_line', { summary: secretSummary(t, config.defaults) }) : t('repo_settings.defaults_none')}
        {/* A link would leave the form and lose what was typed: only the read-only view offers it. */}
        {canEdit ? <span>{t('repo_settings.defaults_where')}</span>
          : <Button size="xs" variant="link" className="h-auto min-h-6 px-0" onClick={() => { setOpen(false); onOpenPolicies() }}>{t('repo_settings.defaults_where')}</Button>}</p>
    </SecretRulesDialog>}
  </>
}
