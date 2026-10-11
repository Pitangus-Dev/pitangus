import { useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CaretRightIcon, CheckCircleIcon, CircleNotchIcon, WarningIcon } from '@phosphor-icons/react'
import { apiPost } from '@/shared/api/client'
import { ApiError } from '@/shared/api/http'
import { domainProbeQuery } from '@/shared/api/queries'
import { useDebounced } from '@/shared/lib/useDebounced'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, dialogFullOnMobile } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Segmented } from '@/shared/ui/segmented'
import type { Domain, DomainKind } from '@/features/domains/domains'

const KINDS = [
  { id: 'web', label: 'domains.kind.web' }, { id: 'api', label: 'domains.kind.api' }, { id: 'surface', label: 'domains.kind.surface' },
] as const
const CONTEXT_MAX = 400
// The server wants https with no port or query; here we only add the scheme people leave out.
const normalize = (value: string) => { const trimmed = value.trim(); return !trimmed || /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}` }
const probeable = (candidate: string) => /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)+\/?[^\s?#]*$/i.test(candidate)

// Registers a site or API (one concept: the kind only tags it); whether it answers is a hint, never a reason to refuse it.
export function AddDomainDialog({ open, onOpenChange, onAdded, initialKind = 'web' }: { open: boolean; onOpenChange: (open: boolean) => void; onAdded: (domain: Domain) => void; initialKind?: DomainKind }) {
  const { t } = useTranslation('sources')
  // The form lives inside the popup: closing unmounts it, so the next opening starts empty.
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className={`max-w-xl ${dialogFullOnMobile}`}>
    <DialogHeader><DialogTitle>{t('domains.add.title')}</DialogTitle><DialogDescription>{t('domains.add.description')}</DialogDescription></DialogHeader>
    <AddDomainForm initialKind={initialKind} onCancel={() => onOpenChange(false)} onAdded={domain => { onAdded(domain); onOpenChange(false) }} />
  </DialogContent></Dialog>
}

function AddDomainForm({ initialKind, onCancel, onAdded }: { initialKind: DomainKind; onCancel: () => void; onAdded: (domain: Domain) => void }) {
  const { t } = useTranslation('sources')
  const [url, setUrl] = useState('')
  const [kind, setKind] = useState<DomainKind>(initialKind)
  const [context, setContext] = useState('')
  const candidate = normalize(url)
  const settled = useDebounced(candidate, 600)
  const probe = useQuery({ ...domainProbeQuery(settled), enabled: probeable(settled) })
  const checking = probeable(candidate) && (settled !== candidate || probe.isFetching)
  const reach = !checking && settled === candidate ? probe.data : undefined
  const probeError = !checking && settled === candidate && probe.error instanceof ApiError ? probe.error.message : ''
  const register = useMutation({
    mutationFn: () => apiPost('/api/domains', 'register-domain', { url: candidate, kind, context }),
    onSuccess: onAdded,
  })
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (!register.isPending) register.mutate() }

  return <form onSubmit={submit} className="space-y-5">
      <div className="space-y-1.5">
        <label htmlFor="domain-url" className="text-sm text-app-secondary">{t('domains.add.domain')}</label>
        <div className="relative">
          <Input id="domain-url" required autoFocus value={url} onChange={event => setUrl(event.target.value)} placeholder={t('domains.add.placeholder')}
            aria-describedby="domain-url-probe" autoComplete="off" spellCheck={false} className="border-input bg-card pr-10" />
          <span className="absolute top-1/2 right-3 -translate-y-1/2" aria-hidden>{checking ? <CircleNotchIcon className="size-4 text-app-muted motion-safe:animate-spin" />
            : reach?.reachable ? <CheckCircleIcon className="size-4 text-success" /> : reach || probeError ? <WarningIcon className="size-4 text-attention" /> : null}</span>
        </div>
        <p id="domain-url-probe" role="status" className="min-h-4 text-xs">
          {checking ? <span className="text-app-muted">{t('domains.add.checking')}</span>
            : reach?.reachable ? <span className="text-success">{t('domains.add.reachable', { code: reach.http_status ?? 200 })}</span>
            : reach ? <span className="text-attention">{t('domains.add.unreachable')} <span className="text-app-muted">{reach.detail}</span></span>
            : probeError ? <span className="text-attention">{probeError}</span> : null}
        </p>
      </div>
      <div className="space-y-2">
        <p aria-hidden className="text-sm text-app-secondary">{t('domains.add.kind')}</p>
        <Segmented label={t('domains.add.kind')} value={kind} onChange={setKind} options={KINDS.map(item => ({ value: item.id, label: t(item.label) }))} />
        {kind === 'surface' && <p className="text-xs text-app-muted">{t('domains.kind_hint.surface')}</p>}
      </div>
      <details className="group">
        <summary className="flex min-h-6 cursor-pointer list-none items-center gap-1.5 text-sm text-app-secondary"><CaretRightIcon className="size-4 motion-safe:transition group-open:rotate-90" aria-hidden />{t('domains.add.more')}</summary>
        <div className="mt-3 space-y-1.5">
          <label htmlFor="domain-context" className="sr-only">{t('domains.add.context')}</label>
          <textarea id="domain-context" rows={3} maxLength={CONTEXT_MAX} value={context} onChange={event => setContext(event.target.value)} aria-describedby="domain-context-help"
            placeholder={t('domains.add.context_placeholder')} className="w-full rounded-xl border border-input bg-card p-3 text-sm focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50" />
          <p id="domain-context-help" className="text-xs text-app-muted">{t('domains.add.context_help')}</p>
        </div>
      </details>
      {register.error && <p role="alert" className="rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger">{register.error.message}</p>}
      <DialogFooter>
        <Button type="button" variant="ghost" onClick={onCancel}>{t('common:actions.cancel')}</Button>
        <Button type="submit" disabled={register.isPending || !url.trim()}>{register.isPending && <CircleNotchIcon className="motion-safe:animate-spin" aria-hidden />}{t('domains.add.submit')}</Button>
      </DialogFooter>
    </form>
}
