import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { apiPost } from '@/shared/api/client'
import { api } from '@/shared/api/http'
import { domainsQuery, keys, registriesQuery, repositoryPlanQuery, sourceCountQuery, sourceQuery, type QueuedDomainScan } from '@/shared/api/queries'
import { formatList } from '@/shared/i18n/format'
import { Switch } from '@/shared/ui/switch'
import type { Source } from '@/features/sources/sources'
import { SarifImport } from '@/features/analyses/sarif-import'
import { useBatches } from '@/features/analyses/use-batches'
import { AccessStep } from '@/features/analyses/wizard/access-step'
import { ContextStep } from '@/features/analyses/wizard/context-step'
import { ImagesStep } from '@/features/analyses/wizard/images-step'
import { RepositoriesStep, type CodeTarget } from '@/features/analyses/wizard/repositories-step'
import { DetailList, LooksFor, OsvOption, ReviewStep, WafNote, type ReviewRow } from '@/features/analyses/wizard/review-step'
import { SpecStep } from '@/features/analyses/wizard/spec-step'
import { StepRail } from '@/features/analyses/wizard/step-frame'
import { TargetStep, type WebTarget } from '@/features/analyses/wizard/target-step'
import { TypeChooser } from '@/features/analyses/wizard/type-chooser'
import { STEPS, duration, listing, referencesOf, registryOf, type Kind, type ScanPlan, type Spec } from '@/features/analyses/wizard/model'

type Start = Kind | 'import' | null
const KIND_TITLE = { code: 'wizard.kinds.code.title', image: 'wizard.kinds.image.title', web: 'wizard.kinds.web.title', api: 'wizard.kinds.api.title' } as const
const CHOOSER = -1

// New scan: choose what to check, answer one question per step, review and launch. Several repositories (or an
// organization, or several images) become a batch that moves forward when the server is free; web and API scans take
// one verified domain. A direct link brings a repository, or a domain with its scan type, already chosen.
export function AnalysisWizard({ onComplete, onBatchStarted, onManageConnections, onCancel, initialSourceId, initialDomainId = null, initialKind = null, isAdmin }: {
  onComplete: (id: string) => Promise<void>; onBatchStarted: () => void; onManageConnections: () => void; onCancel: () => void
  initialSourceId: string | null; initialDomainId?: string | null; initialKind?: Start; isAdmin: boolean
}) {
  const { t } = useTranslation('analyses')
  const queryClient = useQueryClient()
  const start: Start = initialSourceId ? 'code' : initialKind
  const [kind, setKind] = useState<Start>(start)
  const [choice, setChoice] = useState<Kind>(start && start !== 'import' ? start : 'code')
  const [step, setStep] = useState(0)
  const [code, setCode] = useState<CodeTarget>({ mode: 'repos', sources: [], organization: '' })
  const [imageText, setImageText] = useState('')
  const [context, setContext] = useState('')
  const [target, setTarget] = useState<WebTarget>({ domain: null, scopeOpen: false, hosts: [] })
  const [spec, setSpec] = useState<Spec | null>(null)
  const [useHeaders, setUseHeaders] = useState(true)
  const [allowOsv, setAllowOsv] = useState(false)
  const [weekly, setWeekly] = useState<boolean | null>(null)

  const domains = useQuery(domainsQuery())
  const registries = useQuery(registriesQuery()).data?.registries
  const { active: activeBatch } = useBatches()
  const linked = useQuery({ ...sourceQuery<Source>(initialSourceId ?? ''), enabled: !!initialSourceId })
  const [seededSource, setSeededSource] = useState(false)
  if (!seededSource && linked.data) { setSeededSource(true); setCode({ ...code, sources: [linked.data] }) }
  // From a domain's page: that domain chosen and, once it's verified, straight to the step after it.
  const [seededDomain, setSeededDomain] = useState(!initialDomainId)
  if (!seededDomain && domains.data) {
    setSeededDomain(true)
    const found = domains.data.items.find(item => item.id === initialDomainId)
    if (found?.verified) { setTarget({ domain: found, scopeOpen: false, hosts: [] }); setStep(1) }
  }

  const steps = kind && kind !== 'import' ? STEPS[kind] : []
  const current = steps[step]
  const domain = target.domain ? domains.data?.items.find(item => item.id === target.domain?.id) ?? target.domain : null
  const references = referencesOf(imageText)
  const orgTotal = useQuery({ ...sourceCountQuery(code.organization), enabled: kind === 'code' && code.mode === 'org' && !!code.organization }).data ?? null
  const single = kind === 'code' && code.mode === 'repos' && code.sources.length === 1 ? code.sources[0].id : null
  const plan = useQuery({ ...repositoryPlanQuery<ScanPlan>(single ?? ''), enabled: !!single })
  const batch = kind === 'code' ? code.mode === 'org' || code.sources.length > 1 : kind === 'image' && references.length > 1
  const hosts = target.scopeOpen ? target.hosts.filter(item => item.included).map(item => item.host) : []
  const headerNames = (domain?.headers ?? []).map(item => item.name)
  const sending = useHeaders && headerNames.length > 0
  const weeklyOn = weekly ?? domain?.schedule === 'weekly'
  const osv = !!plan.data?.osv_needed && allowOsv

  const restart = () => { setKind(null); setStep(0) }
  const jump = (index: number) => index === CHOOSER ? restart() : setStep(index)
  const back = () => step === 0 ? restart() : setStep(step - 1)
  const next = () => setStep(step + 1)

  const launch = useMutation({
    mutationFn: async (): Promise<string | null> => {
      if ((kind === 'web' || kind === 'api') && domain) {
        const source = kind === 'api' && spec ? spec.mode === 'file' ? { spec: { filename: spec.filename, content_base64: spec.content } } : { spec_url: spec.url } : {}
        const queued = await api.post<QueuedDomainScan>('/api/domains/scans', 'scan-domain', { domain_id: domain.id, mode: kind, ...(hosts.length ? { hosts } : {}), use_headers: sending, ...source })
        // The scan is queued either way; a schedule that didn't save shows on the domain's page, not as a failed launch.
        if (weeklyOn !== (domain.schedule === 'weekly')) await apiPost('/api/domains/schedule', 'schedule-domain', { domain_id: domain.id, schedule: weeklyOn ? 'weekly' : null }).catch(() => null)
        void queryClient.invalidateQueries({ queryKey: keys.domains })
        return queued.run_id
      }
      if (batch) {
        if (kind === 'image') await api.post('/api/images/batches', 'scan-image-batch', { references, context })
        else if (code.mode === 'org') await api.post('/api/repositories/batches', 'scan-batch', { account: code.organization, context })
        else await api.post('/api/repositories/batches', 'scan-batch', { source_ids: code.sources.map(item => item.id), context })
        return null
      }
      const data = kind === 'image'
        ? await api.post<{ run: { id: string } }>('/api/images/scans', 'scan-image', { reference: references[0], context })
        : await api.post<{ run: { id: string } }>('/api/repositories/scans', 'scan-repository', { source_id: single, allow_osv_upload: osv, context })
      return data.run.id
    },
    onSuccess: async id => { if (id) await onComplete(id); else onBatchStarted() },
  })

  if (kind === 'import') return <SarifImport onOpenRun={onComplete} onBack={restart} />
  if (!kind) return <TypeChooser choice={choice} onChoose={setChoice} onContinue={() => { setKind(choice); setStep(0) }} onImport={() => setKind('import')}
    onCancel={onCancel} dast={domains.data?.dast} isAdmin={isAdmin} />

  const where = { label: t('review.where'), value: t('review.where_value') }
  const typeRow = { label: t('review.type'), value: t(KIND_TITLE[kind]), step: CHOOSER }
  const contextIndex = steps.indexOf('context')
  const contextRow: ReviewRow = context.trim() ? { label: t('review.context'), value: context.trim(), step: contextIndex }
    : { label: t('review.context'), value: <Trans t={t} i18nKey="review.no_context" components={{ add: <button type="button" onClick={() => setStep(contextIndex)} className="min-h-6 font-medium text-brand underline underline-offset-2" /> }} /> }

  const review = () => {
    if (kind === 'code') {
      const names = listing(t, code.sources.map(item => item.name))
      const value = code.mode === 'org' ? orgTotal ? t('review.org_value', { name: code.organization, count: orgTotal, duration: duration(t, orgTotal * 60) }) : code.organization
        : code.sources.length > 1 ? t('review.target_repositories', { total: code.sources.length, names }) : names
      const rows = [typeRow, { label: t(code.mode === 'org' ? 'review.organization' : 'review.repositories'), value, step: 0 },
        { label: t('review.looks_for'), value: <LooksFor plan={plan.data} failed={plan.isError} batch={batch} osv={osv} /> }, contextRow, where]
      const label = code.mode === 'org' ? orgTotal ? t('launch.organization_count', { total: orgTotal }) : t('launch.organization')
        : code.sources.length > 1 ? t('launch.repositories', { total: code.sources.length }) : t('launch.code')
      return { rows, label,
        options: !batch && plan.data?.osv_needed ? <OsvOption checked={allowOsv} onChange={setAllowOsv} /> : undefined,
        notes: batch ? <p className="text-sm text-app-muted">{t('review.batch_note')}</p> : undefined,
        details: <>{plan.data && !batch && <>
          {plan.data.languages.length > 0 && <DetailList title={t('details.languages')} items={plan.data.languages.map(item => `${item.name} · ${item.rules ? t('details.rules', { count: item.rules }) : t('details.no_rules')}`)} />}
          <DetailList title={t('details.runs')} items={plan.data.runs} />
          {plan.data.skips.length > 0 && <DetailList title={t('details.skips')} items={plan.data.skips} />}</>}
          {(batch || !plan.data) && <p>{t('details.code_generic')}</p>}
          {batch && <p>{t('details.batch')}</p>}</> }
    }
    if (kind === 'image') {
      const registriesUsed = Array.from(new Set(references.map(registryOf).filter((item): item is string => !!item)))
      const access = registriesUsed.map(host => registries?.some(entry => entry.registry === host) ? t('review.registry_saved', { registry: host }) : t('review.registry_public', { registry: host }))
      const value = references.length > 1 ? t('review.target_images', { total: references.length, names: listing(t, references) }) : references[0]
      return { rows: [typeRow, { label: t('review.images'), value, step: 0 }, { label: t('review.registry'), value: access.join(' · '), step: 0 }, contextRow, where],
        label: references.length > 1 ? t('launch.images', { total: references.length }) : t('launch.image'),
        notes: batch ? <p className="text-sm text-app-muted">{t('review.batch_note')}</p> : undefined,
        details: <>
          <DetailList title={t('details.runs')} items={[t('details.image_runs.packages'), t('details.image_runs.secrets'), t('details.image_runs.config'), t('details.image_runs.checkov'), t('details.image_runs.priority')]} />
          <DetailList title={t('details.skips')} items={[t('details.image_skips.run'), t('details.image_skips.source'), t('details.image_skips.secrets')]} />
          {batch && <p>{t('details.batch')}</p>}</> }
    }
    const host = domain?.host ?? ''
    const specRow = spec ? spec.mode === 'file' ? `${spec.filename} · ${t('spec.summary', { version: spec.version, count: spec.endpoints })}` : spec.url : ''
    const rows: ReviewRow[] = [typeRow, { label: t('review.target'), value: host, step: 0 },
      ...(kind === 'api' ? [{ label: t('review.spec'), value: specRow, step: 1 }] : []),
      { label: t('review.scope'), value: hosts.length ? t('review.scope_value', { host, count: hosts.length }) : t('review.scope_root_only', { host }), step: 0 },
      { label: t('review.access'), value: sending ? t('review.access_value', { count: headerNames.length, names: formatList(headerNames) }) : t('review.access_none'), step: steps.indexOf('access') },
      { label: t('review.context'), value: domain?.context || t('review.no_domain_context') },
      { label: t('review.mode'), value: t('review.mode_passive') }, where]
    return { rows, label: kind === 'api' ? t('launch.api') : t('launch.web'),
      options: <Switch id="weekly-scan" checked={weeklyOn} onCheckedChange={setWeekly} label={t('review.schedule')} hint={t('review.schedule_note')} />,
      notes: <WafNote />,
      details: <DetailList title={t('details.runs')} items={[kind === 'api' ? t('details.api_operations') : t('details.web_crawl', { host }), t('details.web_rules'), t('details.web_hosts'), t('details.web_recheck')]} /> }
  }

  const view = (() => {
    const frame = { onBack: back, onContinue: next }
    if (current === 'repositories') return <RepositoriesStep value={code} onChange={setCode} orgTotal={orgTotal} isAdmin={isAdmin} loading={!!initialSourceId && linked.isPending} batchBusy={!!activeBatch} onManageConnections={onManageConnections} {...frame} />
    if (current === 'images') return <ImagesStep text={imageText} onText={setImageText} registries={registries} batchBusy={!!activeBatch} onManageConnections={onManageConnections} {...frame} />
    if (current === 'context') return <ContextStep value={context} onChange={setContext} {...frame} />
    if (current === 'target' && (kind === 'web' || kind === 'api')) return <TargetStep kind={kind} value={target} {...frame}
      onChange={value => { if (value.domain?.id !== target.domain?.id) { setSpec(null); setUseHeaders(true); setWeekly(null) } setTarget(value) }} />
    if (current === 'spec' && domain) return <SpecStep host={domain.host} scopeHosts={hosts} value={spec} onChange={setSpec} {...frame} />
    if (current === 'access' && domain) return <AccessStep domain={domain} useHeaders={useHeaders} onUseHeaders={setUseHeaders} {...frame} />
    if (current === 'review') {
      const content = review()
      return <ReviewStep kind={kind} batch={batch} authorization={kind === 'web' || kind === 'api'} rows={content.rows} options={content.options} notes={content.notes} details={content.details}
        error={launch.error?.message ?? ''} busy={launch.isPending} launchLabel={content.label} onChange={jump} onBack={back} onLaunch={() => { if (!launch.isPending) launch.mutate() }} />
    }
    return null
  })()

  return <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_220px]">
    <div key={`${kind}-${current}`} className="min-w-0 space-y-4">
      {linked.isError && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{linked.error.message}</p>}
      {view}
    </div>
    <StepRail steps={steps} current={step} onJump={setStep} />
  </div>
}
