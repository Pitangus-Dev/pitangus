import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Globe2, Plus } from 'lucide-react'
import { domainsQuery, keys } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { SkeletonList } from '@/shared/ui/loading'
import { Switch } from '@/shared/ui/switch'
import { AddDomainDialog } from '@/features/domains/add-domain-dialog'
import { TONE, coversSubdomains, kindOf, verification, type Domain } from '@/features/domains/domains'
import { VerifyDomainDialog } from '@/features/domains/verify-domain-dialog'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import { ScopeEditor } from '@/features/analyses/wizard/scope-editor'
import type { ScopeHost } from '@/features/analyses/wizard/model'

export type WebTarget = { domain: Domain | null; scopeOpen: boolean; hosts: ScopeHost[] }

// One verified domain. Unverified ones stay listed with a way to verify them here; the server checks the proof, the
// addresses and the switch again before anything is sent, so this is guidance, not the guard.
export function TargetStep({ kind, value, onChange, onBack, onContinue }: { kind: 'web' | 'api'; value: WebTarget; onChange: (next: WebTarget) => void; onBack: () => void; onContinue: () => void }) {
  const { t } = useTranslation('analyses')
  const queryClient = useQueryClient()
  const domains = useQuery(domainsQuery())
  const [adding, setAdding] = useState(false)
  const [verifying, setVerifying] = useState<Domain | null>(null)
  const items = [...(domains.data?.items ?? [])].sort((a, b) => kind === 'api' ? Number(b.kind === 'api') - Number(a.kind === 'api') : 0)
  const selected = value.domain
  const pick = (domain: Domain) => onChange({ domain, scopeOpen: false, hosts: [] })
  const refresh = () => void queryClient.invalidateQueries({ queryKey: keys.domains })
  const addButton = <Button variant={items.length ? 'outline' : 'default'} onClick={() => setAdding(true)}><Plus aria-hidden />{t('target.add')}</Button>

  return <StepFrame title={t('target.title')} onBack={onBack} onContinue={onContinue} continueDisabled={!selected?.verified}>
    {domains.isPending ? <SkeletonList rows={3} dense label={t('target.loading')} />
      : domains.isError ? <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{domains.error.message}
          <Button size="xs" variant="outline" onClick={() => void domains.refetch()}>{t('common:actions.retry')}</Button></div>
      : !items.length ? <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-app-line py-12 text-center">
          <Globe2 className="size-6 text-app-muted" aria-hidden /><p className="text-sm font-medium">{t('target.empty_title')}</p>
          <p className="max-w-sm text-sm text-app-muted">{t('target.empty_text')}</p>{addButton}</div>
      : <div className="space-y-3">
          <div role="radiogroup" aria-label={t('target.choose')} className="space-y-2">{items.map(domain => {
            const state = verification(domain)
            const on = selected?.id === domain.id
            return <div key={domain.id} className={`flex flex-wrap items-center gap-3 rounded-xl border p-3 text-sm motion-safe:transition ${!domain.verified ? 'border-app-line bg-inset' : on ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-inset hover:border-brand/30'}`}>
              <label className={`flex min-w-0 flex-1 items-center gap-3 ${domain.verified ? 'cursor-pointer' : 'cursor-not-allowed'}`}>
                <input type="radio" name="web-target" value={domain.id} checked={on} disabled={!domain.verified} onChange={() => pick(domain)} className="size-4 accent-brand" />
                <span className="min-w-0"><span className={`block truncate font-medium ${domain.verified ? '' : 'text-app-muted'}`}>{domain.host}</span>
                  <span className="text-xs text-app-muted">{kindOf(domain)}</span></span>
              </label>
              <span className={`rounded-md border px-1.5 text-xs ${TONE[state.tone]}`}>{state.label}</span>
              {!domain.verified && <Button size="sm" variant="outline" aria-label={t('target.verify_for', { host: domain.host })} onClick={() => setVerifying(domain)}>{t('target.verify')}</Button>}
            </div>
          })}</div>
          {addButton}
        </div>}
    {selected?.verified && (coversSubdomains(selected)
      ? <div className="space-y-3">
          <Switch id="scope-toggle" checked={value.scopeOpen} onCheckedChange={scopeOpen => onChange({ ...value, scopeOpen })} label={t('scope.toggle')} />
          {value.scopeOpen && <ScopeEditor root={selected.host} hosts={value.hosts} onChange={hosts => onChange({ ...value, hosts })} />}
        </div>
      : <p className="text-sm text-app-muted">{t('scope.exact_only', { host: selected.host })}</p>)}
    <AddDomainDialog open={adding} onOpenChange={setAdding} initialKind={kind} onAdded={domain => { refresh(); setVerifying(domain) }} />
    <VerifyDomainDialog domain={verifying} onOpenChange={open => { if (!open) setVerifying(null) }} onVerified={domain => { refresh(); pick(domain) }} />
  </StepFrame>
}
