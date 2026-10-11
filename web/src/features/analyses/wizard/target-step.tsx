import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { GlobeIcon, PlusIcon } from '@phosphor-icons/react'
import { domainsQuery, keys } from '@/shared/api/queries'
import { Button } from '@/shared/ui/button'
import { SkeletonList } from '@/shared/ui/loading'
import { Switch } from '@/shared/ui/switch'
import { AddDomainDialog } from '@/features/domains/add-domain-dialog'
import { TONE, coversSubdomains, kindOf, verification, type Domain } from '@/features/domains/domains'
import { VerifyDomainDialog } from '@/features/domains/verify-domain-dialog'
import { ApiDocs } from '@/features/analyses/wizard/api-docs'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import { DomainScopeEditor } from '@/features/domains/domain-scope'
import type { Spec } from '@/features/analyses/wizard/model'

// `scopeOpen`: the scan includes the hosts saved in the domain's scope (edited here, saved on the domain).
export type WebTarget = { domain: Domain | null; scopeOpen: boolean }

// One verified domain, its scope and, optionally, its API documentation. Unverified domains stay listed with a way to
// verify them here; the server checks the proof, the addresses and the switch again before anything is sent.
export function TargetStep({ value, onChange, spec, onSpec, specInvalid, onBack, onContinue }: {
  value: WebTarget; onChange: (next: WebTarget) => void; spec: Spec | null; onSpec: (spec: Spec | null) => void; specInvalid: boolean; onBack: () => void; onContinue: () => void
}) {
  const { t } = useTranslation('analyses')
  const queryClient = useQueryClient()
  const domains = useQuery(domainsQuery())
  const [adding, setAdding] = useState(false)
  const [verifying, setVerifying] = useState<Domain | null>(null)
  const items = (domains.data?.items ?? []).filter(domain => domain.kind !== 'surface')
  const selected = value.domain
  const pick = (domain: Domain) => onChange({ domain, scopeOpen: false })
  const refresh = () => void queryClient.invalidateQueries({ queryKey: keys.domains })
  const addButton = <Button variant={items.length ? 'ghost' : 'default'} onClick={() => setAdding(true)} className={items.length ? 'text-app-secondary' : undefined}><PlusIcon aria-hidden />{t('target.add')}</Button>

  return <StepFrame title={t('target.title')} onBack={onBack} onContinue={onContinue} continueDisabled={!selected?.verified || specInvalid}>
    {domains.isPending ? <SkeletonList rows={3} dense label={t('target.loading')} />
      : domains.isError ? <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{domains.error.message}
          <Button size="xs" variant="outline" onClick={() => void domains.refetch()}>{t('common:actions.retry')}</Button></div>
      : !items.length ? <div className="flex flex-col items-center gap-3 px-4 py-12 text-center">
          <GlobeIcon className="size-6 text-app-muted" aria-hidden /><p className="text-sm text-app-muted">{t('target.empty')}</p>{addButton}</div>
      : <div className="space-y-2">
          <div role="radiogroup" aria-labelledby="wizard-step-title" className="divide-y divide-app-line rounded-xl border border-app-line">{items.map(domain => {
            const on = selected?.id === domain.id
            const state = verification(domain)
            return <div key={domain.id} className={`flex flex-wrap items-center gap-3 px-4 py-3 text-sm first:rounded-t-lg last:rounded-b-lg motion-safe:transition ${on ? 'bg-app-soft' : ''}`}>
              <label className={`flex min-w-0 flex-1 basis-56 items-center gap-3 ${domain.verified ? 'cursor-pointer' : 'cursor-not-allowed'}`}>
                <input type="radio" name="web-target" value={domain.id} checked={on} disabled={!domain.verified} onChange={() => pick(domain)} className="size-4 accent-brand" />
                <span className={`min-w-0 truncate font-medium ${domain.verified ? '' : 'text-app-muted'}`}>{domain.host}</span>
                <span className="shrink-0 text-xs text-app-muted">{kindOf(domain)}</span>
              </label>
              {!domain.verified && <>
                <span className={`rounded-md border px-1.5 text-xs ${TONE[state.tone]}`}>{state.label}</span>
                <Button size="sm" variant="outline" aria-label={t('target.verify_for', { host: domain.host })} onClick={() => setVerifying(domain)}>{t('target.verify')}</Button>
              </>}
            </div>
          })}</div>
          {addButton}
        </div>}
    {selected?.verified && <div className="space-y-8 pt-2">
      {coversSubdomains(selected)
        ? <div className="space-y-3">
            <Switch id="scope-toggle" checked={value.scopeOpen} onCheckedChange={scopeOpen => onChange({ ...value, scopeOpen })} label={t('scope.toggle')}
              hint={value.scopeOpen ? t('scope.toggle_hint') : undefined} />
            {value.scopeOpen && <DomainScopeEditor key={selected.id} domain={selected} admin autoSearch />}
          </div>
        : <p className="text-sm text-app-muted">{t('scope.exact_only', { host: selected.host })}</p>}
      <ApiDocs key={selected.id} host={selected.host} isApi={selected.kind === 'api'} value={spec} invalid={specInvalid} onChange={onSpec} />
    </div>}
    <AddDomainDialog open={adding} onOpenChange={setAdding} onAdded={domain => { refresh(); setVerifying(domain) }} />
    <VerifyDomainDialog domain={verifying} onOpenChange={open => { if (!open) setVerifying(null) }} onVerified={domain => { refresh(); pick(domain) }} />
  </StepFrame>
}
