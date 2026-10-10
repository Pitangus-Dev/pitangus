import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ExternalLink, Globe2, Plus } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { useConfirm } from '@/shared/ui/confirm'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { SkeletonList } from '@/shared/ui/loading'
import { apiPost } from '@/shared/api/client'
import { domainsQuery, keys } from '@/shared/api/queries'
import { formatDay } from '@/shared/i18n/format'
import { BRAND } from '@/shared/lib/brand'
import { AddDomainDialog, VerifyDomainDialog } from '@/features/sources/domain-dialogs'
import { kindOf, type Domain } from '@/features/sources/domains'

const DOCS = `${BRAND.repo}/blob/main/docs/integrations.md#bring-your-own-dast`

// The domains a team owns, each with whether its DNS TXT proof is current. A verified domain is the asset
// `domain:<host>` that a pipeline imports its own ZAP or Nuclei results against; nothing on this page scans anything.
// Administrators add, verify and remove; everyone else reads (the TXT record never reaches them).
export function DomainList({ admin, onOpenFindings }: { admin: boolean; onOpenFindings: (key: string) => void }) {
  const { t } = useTranslation('sources')
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const addOpener = useRef<HTMLButtonElement>(null)
  const [adding, setAdding] = useState(false)
  const [verifying, setVerifying] = useState<Domain | null>(null)
  const [notice, setNotice] = useState('')
  const domains = useQuery(domainsQuery())
  const items = domains.data?.items ?? []
  const refresh = () => queryClient.invalidateQueries({ queryKey: keys.domains })
  const added = (domain: Domain) => {
    void refresh()
    setNotice(t('domains.list.added', { host: domain.host }))
    setVerifying(domain)
  }
  const verified = (domain: Domain) => {
    void refresh()
    setNotice(t('domains.list.verified_notice', { host: domain.host, date: until(domain) }))
  }
  const removal = useMutation({
    mutationFn: (domain: Domain) => apiPost('/api/domains/remove', 'remove-domain', { domain_id: domain.id }),
    onSuccess: (_, domain) => {
      setNotice(t('domains.list.removed', { host: domain.host }))
      void refresh()
      void queryClient.invalidateQueries({ queryKey: keys.assets })
      addOpener.current?.focus()
    },
  })
  const remove = (domain: Domain) => void confirm({
    title: t('domains.list.remove_title', { host: domain.host }),
    description: domain.runs ? t('domains.list.confirm_remove_runs', { count: domain.runs }) : t('domains.list.confirm_remove'),
    confirmLabel: t('domains.list.remove'), destructive: true,
  }).then(ok => { if (ok) removal.mutate(domain) })
  const until = (domain: Domain) => domain.verified_until ? formatDay(domain.verified_until, { dateStyle: 'medium' }) : ''
  const status = (domain: Domain) => domain.verified
    ? { className: 'border-success-line bg-success-soft text-success', label: domain.verified_until ? t('domains.list.verified_until', { date: until(domain) }) : t('domains.list.verified') }
    : domain.expired ? { className: 'border-warning-line bg-warning-soft text-warning', label: t('domains.list.expired') }
    : { className: 'border-warning-line bg-warning-soft text-warning', label: t('domains.list.pending') }
  const example = items.find(domain => domain.verified)?.host ?? items[0]?.host ?? 'app.example.com'

  return <Card className="border-app-line bg-panel">
    <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
      <div className="min-w-0 space-y-1.5"><CardTitle className="text-base">{t('domains.list.title')}</CardTitle><CardDescription>{t('domains.list.description')}</CardDescription></div>
      {admin && <Button ref={addOpener} size="sm" onClick={() => setAdding(true)}><Plus aria-hidden />{t('domains.list.add')}</Button>}
    </CardHeader>
    <CardContent className="space-y-4">
      {!admin && <p className="text-xs text-app-muted">{t('domains.list.read_only')}</p>}
      <div role="status">{notice && <p className="rounded-xl border border-success-line bg-success-soft px-3 py-2 text-sm text-success">{notice}</p>}</div>
      {domains.isError ? <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('domains.list.load_failed')}</p>
      : !domains.data ? <SkeletonList rows={3} label={t('domains.list.loading')} />
      : !items.length ? <div className="flex flex-wrap items-center gap-2 text-sm text-app-muted"><p>{t('domains.list.empty')}{admin ? ` ${t('domains.list.empty_admin')}` : ''}</p></div>
      : <ul aria-busy={domains.isFetching || undefined} className={`divide-y divide-app-line overflow-hidden rounded-xl border border-app-line motion-safe:transition-opacity ${domains.isFetching ? 'opacity-60' : ''}`}>{items.map(domain => {
          const state = status(domain)
          const removeError = removal.isError && removal.variables?.id === domain.id ? removal.error.message : ''
          return <li key={domain.id} className="space-y-2 px-4 py-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <p className="flex min-w-0 flex-wrap items-center gap-2 text-sm font-medium"><Globe2 className="size-4 shrink-0 text-app-muted" aria-hidden /><span className="truncate">{domain.host}</span>
                  <span className="shrink-0 rounded-md border border-app-line bg-inset px-1.5 text-[11px] font-normal text-app-muted">{kindOf(domain)}</span>
                  <span className={`shrink-0 rounded-md border px-1.5 text-[11px] font-normal ${state.className}`}>{state.label}</span></p>
                <p className="text-xs text-app-muted"><span className="font-mono break-all">{domain.key}</span>
                  {domain.runs ? <span> · {t('domains.list.runs', { count: domain.runs })} · {t('domains.list.open', { count: domain.open })}</span> : null}
                  {domain.checked_at && <span> · {t('domains.list.checked', { date: formatDay(domain.checked_at, { dateStyle: 'short' }) })}</span>}</p>
                {domain.context && <p className="text-xs text-app-subtle">{domain.context}</p>}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {domain.runs > 0 && <Button size="sm" variant="outline" className="border-app-line bg-app-soft" aria-label={t('domains.list.findings_for', { host: domain.host })} onClick={() => onOpenFindings(domain.key)}>{t('domains.list.findings')}</Button>}
                {admin && <Button size="sm" variant={domain.verified ? 'ghost' : 'outline'} className={domain.verified ? '' : 'border-app-line bg-app-soft'}
                  aria-label={domain.verified ? t('domains.list.txt_for', { host: domain.host }) : t('domains.list.verify_for', { host: domain.host })}
                  onClick={() => setVerifying(domain)}>{domain.verified ? t('domains.list.txt') : t('domains.list.verify')}</Button>}
                {admin && <Button size="sm" variant="ghost" className="text-danger hover:text-danger" disabled={removal.isPending && removal.variables?.id === domain.id}
                  aria-label={t('domains.list.remove_for', { host: domain.host })} onClick={() => remove(domain)}>{t('domains.list.remove')}</Button>}
              </div>
            </div>
            {removeError && <p role="alert" className="text-xs text-danger">{removeError}</p>}
          </li>
        })}</ul>}
      <div className="space-y-1 text-xs text-app-muted">
        <p>{t('domains.list.import_hint')}</p>
        <code className="block overflow-x-auto rounded-lg border border-app-line bg-inset px-3 py-2 font-mono text-app-secondary">{`python -m pitangus import-sarif zap.sarif --asset domain:${example} --server https://pitangus.example.com`}</code>
        <a href={DOCS} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-brand underline-offset-2 hover:underline">{t('domains.list.docs')} <ExternalLink className="size-3" aria-hidden /><span className="sr-only">{t('new_tab')}</span></a>
      </div>
      <AddDomainDialog open={adding} onOpenChange={setAdding} onAdded={added} />
      <VerifyDomainDialog domain={verifying} onOpenChange={open => { if (!open) setVerifying(null) }} onVerified={verified} />
    </CardContent>
  </Card>
}
