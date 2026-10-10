import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { Globe2, Info, Plus, ShieldCheck } from 'lucide-react'
import { domainsQuery, keys } from '@/shared/api/queries'
import { AddDomainDialog, VerifyDomainDialog } from '@/features/sources/domain-dialogs'
import { kindOf, type Domain } from '@/features/sources/domains'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { SkeletonList } from '@/shared/ui/loading'

// One verified domain for a passive web scan. Only verified domains can be picked; the server checks the proof, the
// addresses and the switch again before ZAP starts, so this is guidance, not the guard.
export function WebTarget({ isAdmin, selected, onSelect, onManageDomains }: { isAdmin: boolean; selected: Domain | null; onSelect: (domain: Domain) => void; onManageDomains: () => void }) {
  const { t } = useTranslation('analyses')
  const queryClient = useQueryClient()
  const domains = useQuery(domainsQuery())
  const [adding, setAdding] = useState(false)
  const [pending, setPending] = useState<Domain | null>(null)
  const items = domains.data?.items ?? []
  const refresh = () => void queryClient.invalidateQueries({ queryKey: keys.domains })
  const manage = <button type="button" onClick={onManageDomains} className="font-medium underline underline-offset-2" />

  return <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('wizard.steps.target')}</CardTitle><CardDescription>{t('web.description')}</CardDescription></CardHeader><CardContent className="space-y-4">
    {domains.data && !domains.data.dast && <p className="flex items-start gap-3 rounded-xl border border-info-line bg-info-soft p-4 text-sm text-app-secondary"><Info className="mt-0.5 size-4 shrink-0 text-info" /><span><Trans t={t} i18nKey="web.disabled" components={{ mono: <span className="font-mono" /> }} /></span></p>}
    {!isAdmin && <p className="flex items-start gap-3 rounded-xl border border-app-line bg-inset p-4 text-sm text-app-muted"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-app-subtle" /><span>{t('web.admin_only')}</span></p>}
    {domains.isPending ? <SkeletonList rows={3} dense label={t('web.loading')} />
      : domains.error ? <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{domains.error.message}</p>
      : !items.length ? <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-app-line py-12 text-center"><Globe2 className="size-6 text-app-subtle" /><p className="text-sm font-medium">{t('web.empty_title')}</p><p className="max-w-sm text-sm text-app-muted">{t('web.empty_text')}</p>
          {isAdmin ? <Button onClick={() => setAdding(true)} className="mt-1 bg-primary text-primary-foreground hover:bg-primary/90"><Plus /> {t('web.register')}</Button>
            : <Button variant="outline" onClick={onManageDomains} className="mt-1 border-app-line bg-app-soft">{t('web.open_domains')}</Button>}</div>
      : <div role="radiogroup" aria-label={t('web.choose')} className="space-y-2">{items.map(domain =>
          <label key={domain.id} className={`flex items-center gap-3 rounded-xl border p-3 text-sm transition ${!domain.verified ? 'cursor-not-allowed border-app-line bg-inset' : selected?.id === domain.id ? 'cursor-pointer border-brand/60 bg-brand/10' : 'cursor-pointer border-app-line bg-inset hover:border-brand/30'}`}>
            <input type="radio" name="web-target" value={domain.id} checked={selected?.id === domain.id} disabled={!domain.verified} onChange={() => onSelect(domain)} className="size-4 accent-brand" />
            <Globe2 className="size-4 shrink-0 text-app-muted" />
            <span className="min-w-0 flex-1"><span className={`block truncate font-medium ${domain.verified ? '' : 'text-app-muted'}`}>{domain.url}</span><span className="text-xs text-app-subtle">{kindOf(domain)}</span></span>
            <Badge variant="outline" className={domain.verified ? 'border-success-line text-success' : 'border-warning-line text-warning'}>{domain.verified ? t('web.verified') : domain.expired ? t('web.expired') : t('web.unverified')}</Badge>
          </label>)}</div>}
    {items.some(domain => !domain.verified) && <p className="text-xs text-app-muted"><Trans t={t} i18nKey="web.unverified_hint" components={{ manage }} /></p>}
    {items.length > 0 && isAdmin && <Button variant="outline" onClick={() => setAdding(true)} className="border-app-line bg-app-soft"><Plus /> {t('web.register')}</Button>}
    {isAdmin && <>
      <AddDomainDialog open={adding} onOpenChange={setAdding} onAdded={domain => { refresh(); setPending(domain) }} />
      <VerifyDomainDialog domain={pending} onOpenChange={() => setPending(null)} onVerified={domain => { refresh(); setPending(null); onSelect(domain) }} />
    </>}
  </CardContent></Card>
}
