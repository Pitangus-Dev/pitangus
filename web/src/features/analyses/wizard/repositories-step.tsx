import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CheckIcon, CodeIcon, LockKeyIcon, PlusIcon, TrashIcon } from '@phosphor-icons/react'
import { sourceAccountsQuery, sourceCountQuery } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, dialogFullOnMobile } from '@/shared/ui/dialog'
import { Segmented } from '@/shared/ui/segmented'
import { SelectField } from '@/shared/ui/select-field'
import { SkeletonList } from '@/shared/ui/loading'
import { SourceSearch } from '@/features/sources/source-search'
import type { Source, SourcePage } from '@/features/sources/sources'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import { BATCH_LIMIT, duration, listing } from '@/features/analyses/wizard/model'

export type CodeTarget = { mode: 'repos' | 'org'; sources: Source[]; organization: string }

// Which repositories: picked by hand (several make a batch) or, for admins with the GitHub App, a whole organization.
export function RepositoriesStep({ value, onChange, orgTotal, isAdmin, batchBusy, loading, onManageConnections, onBack, onContinue }: {
  value: CodeTarget; loading: boolean; onChange: (next: CodeTarget) => void; orgTotal: number | null; isAdmin: boolean; batchBusy: boolean
  onManageConnections: () => void; onBack: () => void; onContinue: () => void
}) {
  const { t } = useTranslation('analyses')
  const [picking, setPicking] = useState(false)
  const accounts = useQuery({ ...sourceAccountsQuery(), enabled: isAdmin }).data ?? []
  const count = useQuery({ ...sourceCountQuery(value.organization), enabled: value.mode === 'org' && !!value.organization })
  const { sources, mode } = value
  const withoutApp = sources.filter(item => !item.installation_id)
  const batch = mode === 'org' || sources.length > 1
  const ready = mode === 'org' ? !!orgTotal : sources.length > 0 && sources.length <= BATCH_LIMIT && (sources.length === 1 || !withoutApp.length)
  const set = (patch: Partial<CodeTarget>) => onChange({ ...value, ...patch })
  const toggle = (item: Source) => set({ sources: sources.some(entry => entry.id === item.id) ? sources.filter(entry => entry.id !== item.id) : [...sources, item] })

  // One line, and only when it applies.
  const note = mode === 'repos' && sources.length > 1 && withoutApp.length ? <p role="status" className="text-sm text-attention">{t('repos.not_in_app', { names: listing(t, withoutApp.map(item => item.name)) })}</p>
    : mode === 'repos' && sources.length > BATCH_LIMIT ? <p role="status" className="text-sm text-danger">{t('repos.over_limit', { limit: BATCH_LIMIT })}</p>
    : batch && batchBusy ? <p role="status" className="text-sm text-app-muted">{t('repos.batch_busy')}</p>
    : batch ? <p role="status" className="text-sm text-app-muted">{t('repos.batch_note')}</p> : null

  return <StepFrame title={t('repos.title')} onBack={onBack} onContinue={onContinue} continueDisabled={!ready || (batch && batchBusy)}>
    {isAdmin && accounts.length > 0 && <Segmented label={t('repos.mode.label')} value={mode} onChange={next => set({ mode: next })}
      options={[{ value: 'repos', label: t('repos.mode.pick') }, { value: 'org', label: t('repos.mode.org') }]} />}
    {mode === 'org'
      ? <div className="max-w-md space-y-1.5">
          <label htmlFor="scan-organization" className="text-sm text-app-secondary">{t('repos.org_label')}</label>
          <SelectField id="scan-organization" value={value.organization} onValueChange={organization => set({ organization })} placeholder={t('repos.org_choose')} options={accounts.map(account => ({ value: account, label: account }))} />
          {value.organization && <p role="status" className="text-sm text-app-muted">{count.isError ? <span className="text-danger">{t('repos.org_count_error', { name: value.organization })}</span>
            : orgTotal === null ? t('repos.org_counting') : orgTotal ? t('repos.org_estimate', { count: orgTotal, duration: duration(t, orgTotal * 60) }) : t('repos.org_none')}</p>}
        </div>
      : loading ? <SkeletonList rows={1} dense label={t('repos.loading')} />
      : sources.length
      ? <div className="space-y-2">
          <ul className="space-y-2">{sources.map(item => <li key={item.id} className="flex items-center justify-between gap-3 rounded-xl border border-app-line bg-inset p-3">
            <span className="flex min-w-0 items-center gap-3"><CodeIcon className="size-4 shrink-0 text-brand" aria-hidden />
              <span className="min-w-0"><span className="block truncate text-sm font-medium">{item.name}</span>
                <span className="text-xs text-app-muted">{item.provider.toUpperCase()} · {item.branch ?? t('repos.default_branch')}{sources.length > 1 && !item.installation_id ? ` · ${t('repos.not_in_app_badge')}` : ''}</span></span></span>
            <Button aria-label={t('remove_item', { name: item.name })} variant="ghost" size="icon-sm" onClick={() => toggle(item)}><TrashIcon /></Button>
          </li>)}</ul>
          <Button variant="outline" onClick={() => setPicking(true)}><PlusIcon aria-hidden />{t('repos.add_more')}</Button>
        </div>
      : <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-app-line px-4 py-12 text-center">
          <CodeIcon className="size-6 text-app-muted" aria-hidden /><p className="text-sm font-medium">{t('repos.empty_title')}</p>
          <p className="max-w-sm text-sm text-app-muted">{t('repos.empty_text')}</p>
          <Button variant="outline" onClick={() => setPicking(true)}><PlusIcon aria-hidden />{t('repos.add')}</Button>
        </div>}
    {note}
    <SourceDialog open={picking} onOpenChange={setPicking} selected={sources.map(item => item.id)} onToggle={toggle} onManageConnections={onManageConnections} />
  </StepFrame>
}

function SourceDialog({ open, onOpenChange, selected, onToggle, onManageConnections }: { open: boolean; onOpenChange: (open: boolean) => void; selected: string[]; onToggle: (source: Source) => void; onManageConnections: () => void }) {
  const { t } = useTranslation('analyses')
  const [connected, setConnected] = useState(true)
  const loaded = useCallback((data: SourcePage) => setConnected(Object.values(data.providers).some(item => item.configured)), [])
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className={`max-w-xl ${dialogFullOnMobile}`}>
    <DialogHeader><DialogTitle>{t('repos.add')}</DialogTitle></DialogHeader>
    {open && <div className="max-h-[60vh] overflow-y-auto pr-1"><SourceSearch autoFocus onLoaded={loaded} render={item => { const on = selected.includes(item.id)
      return <button type="button" aria-pressed={on} onClick={() => onToggle(item)} className={`flex w-full items-center gap-3 rounded-xl border p-3 text-left motion-safe:transition ${on ? 'border-app-fg bg-app-soft' : 'border-app-line bg-inset hover:border-app-faint'}`}>
        <CodeIcon className="size-4 shrink-0 text-app-muted" aria-hidden />
        <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{item.name}</span>
          <span className="text-xs text-app-muted">{item.provider.toUpperCase()} · {item.branch ?? t('repos.default_branch')}{item.installation_id ? '' : ` · ${t('repos.not_in_app_single')}`}</span></span>
        {on ? <CheckIcon className="size-4 text-brand" aria-hidden /> : item.private ? <LockKeyIcon className="size-4 text-app-muted" aria-hidden /> : null}</button> }} /></div>}
    {!connected && <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-app-line bg-inset p-4 text-sm"><span className="text-app-muted">{t('repos.no_provider')}</span>
      <Button variant="outline" onClick={onManageConnections}>{t('repos.connect')}</Button></div>}
    <DialogFooter><span className="mr-auto text-xs text-app-muted">{t('repos.selected', { count: selected.length })}</span><Button onClick={() => onOpenChange(false)}>{t('repos.done')}</Button></DialogFooter>
  </DialogContent></Dialog>
}
