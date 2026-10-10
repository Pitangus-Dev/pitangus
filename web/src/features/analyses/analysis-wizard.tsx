import { useCallback, useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { api, query } from '@/shared/api/http'
import { ArrowLeft, ArrowRight, Boxes, Braces, Check, Code2, FileUp, Globe2, KeyRound, Layers3, LoaderCircle, LockKeyhole, Plus, SearchCheck, ShieldCheck, Trash2, TriangleAlert, X } from 'lucide-react'
import type { Domain } from '@/features/sources/domains'
import { WebTarget } from '@/features/analyses/web-target'
import { domainsQuery } from '@/shared/api/queries'
import { SoonBadge } from '@/shared/ui/coming-soon'
import { Button } from '@/shared/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/shared/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/shared/ui/dialog'
import { SourceSearch } from '@/features/sources/source-search'
import { fetchSource, type Source, type SourcePage } from '@/features/sources/sources'
import { SkeletonCard } from '@/shared/ui/loading'
import { useBatches } from '@/features/analyses/use-batches'
import { SarifImport } from '@/features/analyses/sarif-import'
import { SelectField } from '@/shared/ui/select-field'

type ScanPlan = { languages: { name: string; files: number; rules: number }[]; runs: string[]; skips: string[]; osv_needed: boolean; files: number | null; manifests: string[]; iac: string[]; pipelines?: string[] }
type Kind = 'code' | 'web' | 'image' | 'import'
type ScanKind = Exclude<Kind, 'import'>
type Registry = { registry: string; username: string; last4: string }

const STEPS: Record<ScanKind, { id: string; label: string }[]> = {
  code: [{ id: 'source', label: 'wizard.steps.source' }, { id: 'context', label: 'wizard.steps.context' }, { id: 'review', label: 'wizard.steps.review' }],
  web: [{ id: 'target', label: 'wizard.steps.target' }, { id: 'review', label: 'wizard.steps.review' }],
  image: [{ id: 'image', label: 'wizard.steps.image' }, { id: 'context', label: 'wizard.steps.context' }, { id: 'review', label: 'wizard.steps.review' }],
}
// Mismo criterio que el servidor: registro opcional (con punto, puerto o localhost), repositorio en minúsculas, etiqueta o digest.
const IMAGE_REFERENCE = /^(?:((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+(?::\d{1,5})?|localhost(?::\d{1,5})?|[a-zA-Z0-9-]+:\d{1,5})\/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*){0,5}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$/
const registryOf = (reference: string) => { const match = reference.trim().match(IMAGE_REFERENCE); return match ? (match[1]?.toLowerCase() ?? 'docker.io') : null }
const BATCH_LIMIT = 100   // repositorios o imágenes por lote elegidos a mano (una organización entera no tiene este tope)
const listing = (t: TFunction<'analyses'>, names: string[], limit = 3) => names.length <= limit ? names.join(', ') : t('listing_more', { names: names.slice(0, limit).join(', '), rest: names.length - limit })
const duration = (t: TFunction<'analyses'>, seconds: number) => seconds < 5400 ? t('duration.minutes', { value: Math.max(1, Math.round(seconds / 60)) }) : t('duration.hours', { value: Math.round(seconds / 3600) })

// Uno o varios: con más de un repositorio (o una organización, o varias imágenes) se crea un lote que avanza cuando el
// servidor está libre; su progreso se ve en Análisis.
export function AnalysisWizard({ onComplete, onBatchStarted, onManageConnections, onManageDomains, onCancel, initialSourceId, isAdmin }: { onComplete: (id: string) => Promise<void>; onBatchStarted: () => void; onManageConnections: () => void; onManageDomains: () => void; onCancel: () => void; initialSourceId: string | null; isAdmin: boolean }) {
  const { t } = useTranslation('analyses')
  const [kind, setKind] = useState<Kind | null>(initialSourceId ? 'code' : null)
  const [choice, setChoice] = useState<Kind>('code')
  const [step, setStep] = useState(0)
  const [chosenSources, setChosenSources] = useState<Source[]>([])
  const [codeMode, setCodeMode] = useState<'repos' | 'org'>('repos')
  const source = codeMode === 'repos' && chosenSources.length === 1 ? chosenSources[0].id : null
  const [accounts, setAccounts] = useState<string[]>([])
  const [organization, setOrganization] = useState('')
  const [orgCount, setOrgCount] = useState<{ account: string; total: number | 'error' } | null>(null)
  const orgResult = orgCount?.account === organization ? orgCount.total : null
  const orgTotal = typeof orgResult === 'number' ? orgResult : null
  // Solo un lote a la vez: con uno en curso se puede lanzar un análisis suelto, no otro lote.
  const { active: activeBatch } = useBatches()
  // A passive web scan takes one verified domain; whether this server runs them comes with the domain list.
  const [webTarget, setWebTarget] = useState<Domain | null>(null)
  const domainPage = useQuery({ ...domainsQuery(), enabled: kind === 'web' })
  const [context, setContext] = useState('')
  const [allowOsv, setAllowOsv] = useState(false)
  const [plan, setPlan] = useState<ScanPlan | null>(null)
  const [planError, setPlanError] = useState('')
  const [pickSource, setPickSource] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [reference, setReference] = useState('')
  const [registries, setRegistries] = useState<Registry[] | null>(null)

  // Un enlace directo trae el id: se pide ese repositorio, no el catálogo.
  useEffect(() => { if (initialSourceId) fetchSource(initialSourceId).then(item => setChosenSources([item])).catch(caught => setError(caught instanceof Error ? caught.message : String(caught))) }, [initialSourceId])
  // Organizaciones conectadas a la GitHub App: analizar una entera es cosa de administración.
  useEffect(() => { if (isAdmin && kind === 'code') api.get<SourcePage>(`/api/sources?${query({ provider: 'github', per_page: 1 })}`).then(data => setAccounts(data.accounts ?? [])).catch(() => setAccounts([])) }, [isAdmin, kind])
  useEffect(() => {
    if (!organization) return
    api.get<{ total: number }>(`/api/sources?${query({ account: organization, provider: 'github', per_page: 1 })}`)
      .then(data => setOrgCount({ account: organization, total: data.total })).catch(() => setOrgCount({ account: organization, total: 'error' }))
  }, [organization])
  // El plan se calcula en el servidor con el árbol real del repositorio y los motores disponibles.
  const [planFor, setPlanFor] = useState({ kind, source })
  if (planFor.kind !== kind || planFor.source !== source) { setPlanFor({ kind, source }); setPlan(null); setPlanError('') }
  useEffect(() => {
    if (kind !== 'code' || !source) return
    let current = true
    api.get<ScanPlan>(`/api/repositories/plan?source_id=${encodeURIComponent(source)}`)
      .then(next => { if (current) setPlan(next) })
      .catch(caught => { if (current) setPlanError(caught instanceof Error ? caught.message : String(caught)) })
    return () => { current = false }
  }, [kind, source])
  useEffect(() => { api.get<{ registries: Registry[] }>('/api/registries').then(data => setRegistries(data.registries)).catch(() => {}) }, [])

  const steps = kind && kind !== 'import' ? STEPS[kind] : []
  const references = Array.from(new Set(reference.split('\n').map(line => line.trim()).filter(Boolean)))
  const invalidReferences = references.filter(item => !registryOf(item))
  const imageRegistries = Array.from(new Set(references.map(registryOf).filter((item): item is string => !!item)))
  const imageRegistry = references.length === 1 ? registryOf(references[0]) : null
  const imageCredentials = registries?.find(item => item.registry === imageRegistry) ?? null
  const withoutApp = chosenSources.filter(item => !item.installation_id)
  const batch = kind === 'code' ? codeMode === 'org' || chosenSources.length > 1 : kind === 'image' && references.length > 1
  const codeReady = codeMode === 'org' ? !!organization && !!orgTotal : chosenSources.length > 0 && chosenSources.length <= BATCH_LIMIT && (chosenSources.length === 1 || !withoutApp.length)
  const imageReady = references.length > 0 && references.length <= BATCH_LIMIT && !invalidReferences.length
  const webReady = isAdmin && !!domainPage.data?.dast && !!webTarget?.verified
  const ready = (kind === 'code' ? codeReady : kind === 'image' ? imageReady : webReady) && !(batch && activeBatch)
  const none = t('review.target_none')
  const sourceNames = listing(t, chosenSources.map(item => item.name))
  const imageNames = listing(t, references)
  const targetLabel = kind === 'code'
    ? codeMode === 'org' ? `${organization ? t('review.target_org', { name: organization }) : t('review.target_org_unset')}${orgTotal ? ` · ${t('common:count.repositories', { count: orgTotal })}` : ''}` : chosenSources.length ? chosenSources.length > 1 ? t('review.target_repositories', { total: chosenSources.length, names: sourceNames }) : sourceNames : none
    : kind === 'image' ? references.length ? references.length > 1 ? t('review.target_images', { total: references.length, names: imageNames }) : imageNames : none
    : webTarget?.url ?? none

  const launch = async () => {
    if (busy || !ready) return
    setBusy(true); setError('')
    try {
      if (batch) {
        if (kind === 'image') await api.post('/api/images/batches', 'scan-image-batch', { references, context })
        else if (codeMode === 'org') await api.post('/api/repositories/batches', 'scan-batch', { account: organization, context })
        else await api.post('/api/repositories/batches', 'scan-batch', { source_ids: chosenSources.map(item => item.id), context })
        onBatchStarted()
        return
      }
      const data = kind === 'web'
        ? await api.post<{ run: { id: string } }>('/api/domains/scans', 'scan-domain', { domain_id: webTarget?.id })
        : kind === 'image'
        ? await api.post<{ run: { id: string } }>('/api/images/scans', 'scan-image', { reference: references[0], context })
        : await api.post<{ run: { id: string } }>('/api/repositories/scans', 'scan-repository', { source_id: source, allow_osv_upload: !!plan?.osv_needed && allowOsv, context })
      await onComplete(data.run.id)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setBusy(false) }
  }

  if (!kind) return <div className="space-y-6">
    <div className="flex items-center justify-between gap-3"><h2 className="text-xl font-semibold">{t('wizard.choose_type')}</h2><Button variant="ghost" onClick={onCancel}><ArrowLeft /> {t('common:actions.back')}</Button></div>
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
      {([['code', Code2, t('run_type.repository_scan'), t('wizard.kinds.code.description'), [t('wizard.kinds.code.sast'), t('wizard.kinds.code.secrets'), t('wizard.kinds.code.dependencies'), t('wizard.kinds.code.iac')]],
         ['image', Boxes, t('run_type.image_scan'), t('wizard.kinds.image.description'), [t('wizard.kinds.image.packages'), t('wizard.kinds.image.secrets'), t('wizard.kinds.image.config')]],
         ['web', Globe2, t('wizard.kinds.web.title'), t('wizard.kinds.web.description'), [t('wizard.kinds.web.dns'), t('wizard.kinds.web.passive'), t('wizard.kinds.web.evidence')]],
         ['import', FileUp, t('run_type.sarif_import'), t('wizard.kinds.import.description'), [t('wizard.kinds.import.tools'), t('wizard.kinds.import.existing'), t('wizard.kinds.import.fixes')]],
         ['api', Braces, t('wizard.kinds.api.title'), t('wizard.kinds.api.description'), [t('wizard.kinds.api.openapi'), t('wizard.kinds.api.safe'), t('wizard.kinds.api.dns')]]] as const).map(([id, Icon, title, description, bullets]) => { const soon = id === 'api'; return <button key={id} disabled={soon} onClick={() => { if (id !== 'api') setChoice(id) }} aria-pressed={soon ? undefined : choice === id} className={`rounded-2xl border p-6 text-left transition ${soon ? 'cursor-not-allowed border-dashed border-app-line bg-inset/40 opacity-60' : choice === id ? 'border-brand/60 bg-brand/[0.07]' : 'border-app-line bg-panel hover:border-brand/30'}`}>
        <div className="flex items-start justify-between gap-3"><div className={`flex size-11 items-center justify-center rounded-2xl ${id === 'web' || id === 'api' ? 'bg-info-soft text-info' : 'bg-brand/15 text-brand'}`}><Icon /></div>{soon ? <SoonBadge /> : <span className={`mt-1 flex size-4 items-center justify-center rounded-full border ${choice === id ? 'border-primary bg-primary' : 'border-app-line'}`}>{choice === id && <Check className="size-3 text-primary-foreground" />}</span>}</div>
        <h3 className="mt-6 text-lg font-semibold">{title}</h3><p className="mt-2 text-sm leading-6 text-app-muted">{description}</p>
        <ul className="mt-5 space-y-1.5">{bullets.map(item => <li key={item} className="flex items-center gap-2 text-xs text-app-subtle"><SearchCheck className="size-3.5 shrink-0" />{item}</li>)}</ul>
      </button> })}
    </div>
    <div className="flex justify-end"><Button onClick={() => { setKind(choice); setStep(0) }} className="bg-primary text-primary-foreground hover:bg-primary/90">{t('wizard.continue')} <ArrowRight /></Button></div>
  </div>

  // Importing is one form, not a scan with steps: the created runs are already finished.
  if (kind === 'import') return <SarifImport onOpenRun={onComplete} onBack={() => { setKind(null); setStep(0) }} />

  const current = steps[step].id
  return <div className="space-y-6">
    <Button variant="ghost" onClick={() => { setKind(null); setStep(0) }}><ArrowLeft /> {t('wizard.back_to_types')}</Button>
    <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_230px]">
      <div className="min-w-0 space-y-5">
        {current === 'source' && <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('wizard.steps.source')}</CardTitle><CardDescription>{isAdmin && accounts.length ? t('source.description_with_org') : t('source.description')}</CardDescription></CardHeader><CardContent className="space-y-4">
          {isAdmin && accounts.length > 0 && <div role="radiogroup" aria-label={t('source.mode.label')} className="grid gap-2 sm:grid-cols-2">
            {([['repos', t('source.mode.repos'), t('source.mode.repos_hint', { limit: BATCH_LIMIT })], ['org', t('source.mode.org'), t('source.mode.org_hint')]] as const).map(([id, title, hint]) =>
              <label key={id} className={`flex cursor-pointer flex-col gap-0.5 rounded-xl border p-3 text-sm ${codeMode === id ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-inset'}`}>
                <span className="flex items-center gap-2"><input type="radio" name="code-mode" value={id} checked={codeMode === id} onChange={() => setCodeMode(id)} className="size-4 accent-brand" /><span className="font-medium">{title}</span></span>
                <span className="pl-6 text-xs text-app-muted">{hint}</span></label>)}
          </div>}
          {codeMode === 'org'
            ? <div className="space-y-2"><label htmlFor="scan-organization" className="text-sm text-app-secondary">{t('org.label')}</label>
                <SelectField id="scan-organization" value={organization} onValueChange={setOrganization} placeholder={t('org.choose')} options={accounts.map(account => ({ value: account, label: account }))} />
                {organization && orgResult === 'error' && <p role="alert" className="text-xs text-danger">{t('org.count_error', { name: organization })}</p>}
                {organization && orgResult !== 'error' && <p role="status" className="text-xs text-app-muted">{orgTotal === null ? t('org.counting') : orgTotal ? <Trans t={t} i18nKey="org.estimate" count={orgTotal} values={{ duration: duration(t, orgTotal * 60) }} components={{ strong: <span /> }} /> : t('org.none')}</p>}</div>
            : chosenSources.length
            ? <div className="space-y-2">{chosenSources.map(item => <div key={item.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-brand/40 bg-brand/[0.07] p-3"><span className="flex min-w-0 items-center gap-3"><Code2 className="size-4 shrink-0 text-brand" /><span className="min-w-0"><span className="block truncate text-sm font-medium">{item.name}</span><span className="text-xs text-app-subtle">{item.provider.toUpperCase()} · {item.branch ?? t('source.default_branch')}{chosenSources.length > 1 && !item.installation_id ? ` · ${t('source.not_in_app')}` : ''}</span></span></span><Button aria-label={t('remove_item', { name: item.name })} variant="ghost" size="icon-sm" onClick={() => setChosenSources(previous => previous.filter(entry => entry.id !== item.id))}><Trash2 /></Button></div>)}
                <Button variant="outline" onClick={() => setPickSource(true)} className="border-app-line bg-app-soft"><Plus /> {t('source.add_more')}</Button></div>
            : <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-app-line py-14 text-center"><Code2 className="size-6 text-app-subtle" /><p className="text-sm font-medium">{t('source.empty_title')}</p><p className="max-w-sm text-sm text-app-muted">{t('source.empty_text')}</p><Button onClick={() => setPickSource(true)} className="mt-1 bg-primary text-primary-foreground hover:bg-primary/90"><Plus /> {t('source.add')}</Button></div>}
          {codeMode === 'repos' && chosenSources.length > 1 && withoutApp.length > 0 && <p className="rounded-xl border border-warning-line bg-warning-soft px-3 py-2 text-xs text-warning">{t('source.without_app', { names: listing(t, withoutApp.map(item => item.name)) })}</p>}
          {codeMode === 'repos' && chosenSources.length > BATCH_LIMIT && <p className="text-xs text-danger">{t('source.over_limit', { limit: BATCH_LIMIT })}</p>}
          {batch && activeBatch && <p role="status" className="rounded-xl border border-app-line bg-inset px-3 py-2 text-xs text-app-muted">{t('source.batch_active', { label: activeBatch.label })}</p>}
          <p className="text-xs text-app-subtle">{batch ? t('source.batch_hint') : t('source.single_hint')}</p>
        </CardContent></Card>}

        {current === 'image' && <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('image.title')}</CardTitle><CardDescription><Trans t={t} i18nKey="image.description" components={{ code: <code className="font-mono" /> }} /></CardDescription></CardHeader><CardContent className="space-y-4">
          <div className="space-y-1.5"><label htmlFor="image-reference" className="text-sm text-app-secondary">{t('image.references')} <span className="text-app-subtle">{t('image.references_hint', { limit: BATCH_LIMIT })}</span></label>
            <textarea id="image-reference" aria-invalid={invalidReferences.length > 0 || references.length > BATCH_LIMIT} aria-describedby="image-reference-help" autoFocus rows={Math.min(8, Math.max(3, references.length + 1))} value={reference} onChange={event => setReference(event.target.value)} maxLength={30_000} spellCheck={false} autoComplete="off" placeholder={t('image.placeholder')} className="w-full rounded-xl border border-app-line bg-app-soft p-3 font-mono text-sm focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50" />
            <div id="image-reference-help">
            {invalidReferences.length > 0 && <p className="text-xs text-danger"><Trans t={t} i18nKey="image.invalid" values={{ names: listing(t, invalidReferences) }} components={{ mono: <span className="font-mono" /> }} /></p>}
            {references.length > BATCH_LIMIT && <p className="text-xs text-danger">{t('image.over_limit', { limit: BATCH_LIMIT })}</p>}
            {references.length > 1 && !invalidReferences.length && <p className="text-xs text-app-muted">{t('image.batch_info', { total: references.length })}</p>}
            {references.length > 1 && activeBatch && <p className="text-xs text-app-muted">{t('image.batch_active', { label: activeBatch.label })}</p>}
            </div>
            {!reference.trim() && <div className="flex flex-wrap items-center gap-1.5 pt-1 text-xs text-app-subtle"><span>{t('image.try_public')}</span>{[['nginx:1.21', t('image.samples.old')], ['nginx:1.27-alpine', t('image.samples.recent')], ['vulnerables/web-dvwa', t('image.samples.vulnerable')]].map(([value, hint]) => <button key={value} type="button" onClick={() => setReference(value)} title={hint} className="rounded-md border border-app-line bg-app-soft px-2 py-0.5 font-mono text-[11px] text-app-secondary hover:border-app-faint">{value}</button>)}</div>}</div>
          {references.length > 1 && registries && imageRegistries.length > 0 && <div className="flex items-start gap-3 rounded-xl border border-app-line bg-inset p-4 text-sm"><KeyRound className="mt-0.5 size-4 shrink-0 text-app-muted" /><span>{imageRegistries.map(item => registries.some(entry => entry.registry === item) ? t('image.registry_saved', { registry: item }) : t('image.registry_anonymous', { registry: item })).join(' · ')}</span></div>}
          {imageRegistry && registries && <div className={`flex items-start gap-3 rounded-xl border p-4 text-sm ${imageCredentials ? 'border-brand/30 bg-brand/[0.06]' : 'border-app-line bg-inset'}`}><KeyRound className="mt-0.5 size-4 shrink-0 text-app-muted" /><span>{imageCredentials
              ? <Trans t={t} i18nKey="image.credentials_saved" values={{ registry: imageRegistry, username: imageCredentials.username, last4: imageCredentials.last4 }} components={{ strong: <strong className="font-medium" /> }} />
              : <Trans t={t} i18nKey="image.credentials_missing" values={{ registry: imageRegistry }} components={{ strong: <strong className="font-medium" />, link: <button type="button" onClick={onManageConnections} className="underline underline-offset-2" /> }} />}</span></div>}
          <p className="text-xs text-app-subtle"><Trans t={t} i18nKey="image.tip" components={{ mono: <span className="font-mono" /> }} /></p>
        </CardContent></Card>}

        {current === 'target' && <WebTarget isAdmin={isAdmin} selected={webTarget} onSelect={setWebTarget} onManageDomains={onManageDomains} />}

        {current === 'context' && <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('wizard.steps.context')}</CardTitle><CardDescription>{t('context.description')}</CardDescription></CardHeader><CardContent className="space-y-3">
          <label htmlFor="run-context" className="text-sm text-app-secondary">{t('context.question')} <span className="text-app-subtle">{t('context.optional')}</span></label>
          <textarea id="run-context" rows={6} maxLength={400} value={context} onChange={event => setContext(event.target.value)} placeholder={t('context.placeholder')} className="w-full rounded-xl border border-app-line bg-app-soft p-3 text-sm outline-none focus-visible:border-brand/60" />
          <p className="text-xs text-app-subtle">{t('context.counter', { length: context.length, max: 400 })}</p>
        </CardContent></Card>}

        {current === 'review' && <div className="space-y-5">
          <Card className="border-app-line bg-panel"><CardHeader><CardTitle>{t('wizard.steps.review')}</CardTitle><CardDescription>{t('review.description')}</CardDescription></CardHeader><CardContent className="space-y-4">
            <Row label={t('review.type')} value={kind === 'code' ? t('run_type.repository_scan') : kind === 'image' ? t('run_type.image_scan') : t('run_type.dast_scan')} />
            <Row label={t('review.target')} value={targetLabel} />
            {kind !== 'web' && <Row label={t('wizard.steps.context')} value={context.trim() || t('review.no_context')} />}
            {batch && <div className="flex items-start gap-3 rounded-xl border border-brand/30 bg-brand/[0.06] p-4 text-sm text-app-secondary"><Layers3 className="mt-0.5 size-4 shrink-0 text-brand" /><span>{kind === 'image' ? t('review.batch_image') : t('review.batch_code')}</span></div>}
            {kind === 'code' && !batch && <>
              {!plan ? <div className="flex items-center gap-2 rounded-xl border border-app-line bg-inset p-4 text-sm text-app-muted">{planError ? <><TriangleAlert className="size-4 text-warning" />{planError}</> : <div className="w-full"><SkeletonCard lines={4} label={t('review.plan_loading')} /></div>}</div> : <>
              {plan.languages.length > 0 && <div className="space-y-2 rounded-xl border border-app-line bg-inset p-4"><p className="text-xs font-medium tracking-widest text-app-subtle uppercase">{plan.files !== null ? t('review.languages_files', { count: plan.files }) : t('review.languages')}</p><div className="flex flex-wrap gap-2">{plan.languages.map(item => <span key={item.name} className={`rounded-lg border px-2 py-1 text-xs ${item.rules ? 'border-brand/30 text-brand' : 'border-warning-line text-warning'}`}>{item.name} · {item.files} · {item.rules ? t('review.rules', { count: item.rules }) : t('review.no_rules')}</span>)}</div></div>}
              <div className="space-y-2 rounded-xl border border-app-line bg-inset p-4"><p className="text-xs font-medium tracking-widest text-app-subtle uppercase">{t('review.runs')}</p>{[...plan.runs, ...(plan.osv_needed && allowOsv ? [t('review.osv_authorized')] : [])].map(item => <p key={item} className="flex gap-2 text-sm text-app-secondary"><Check className="mt-0.5 size-4 shrink-0 text-brand" />{item}</p>)}</div>
              <div className="space-y-2 rounded-xl border border-app-line bg-inset p-4"><p className="text-xs font-medium tracking-widest text-app-subtle uppercase">{t('review.skips')}</p>{plan.skips.map(item => <p key={item} className="flex gap-2 text-sm text-app-muted"><X className="mt-0.5 size-4 shrink-0 text-app-subtle" />{item}</p>)}</div>
              {plan.osv_needed && <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-app-line bg-inset p-4 text-xs leading-5"><input type="checkbox" checked={allowOsv} onChange={event => setAllowOsv(event.target.checked)} className="mt-0.5 accent-brand" /><span><Trans t={t} i18nKey="review.osv_consent" components={{ strong: <strong className="text-app-secondary" />, mono: <span className="font-mono" /> }} /></span></label>}
              </>}
            </>}
            {kind === 'image' && <>
              <div className="space-y-2 rounded-xl border border-app-line bg-inset p-4"><p className="text-xs font-medium tracking-widest text-app-subtle uppercase">{t('review.runs')}</p>{[t('review.image_runs.packages'), t('review.image_runs.secrets'), t('review.image_runs.config'), t('review.image_runs.checkov'), t('review.image_runs.priority'), imageCredentials ? t('review.image_runs.saved_credentials', { registry: imageRegistry }) : t('review.image_runs.anonymous')].map(item => <p key={item} className="flex gap-2 text-sm text-app-secondary"><Check className="mt-0.5 size-4 shrink-0 text-brand" />{item}</p>)}</div>
              <div className="space-y-2 rounded-xl border border-app-line bg-inset p-4"><p className="text-xs font-medium tracking-widest text-app-subtle uppercase">{t('review.skips')}</p>{[t('review.image_skips.run'), t('review.image_skips.source'), t('review.image_skips.secrets')].map(item => <p key={item} className="flex gap-2 text-sm text-app-muted"><X className="mt-0.5 size-4 shrink-0 text-app-subtle" />{item}</p>)}</div>
            </>}
            {kind === 'web' && webTarget && <>
              <div className="space-y-2 rounded-xl border border-app-line bg-inset p-4"><p className="text-xs font-medium tracking-widest text-app-subtle uppercase">{t('review.runs')}</p>{[t('review.web_runs.spider', { host: webTarget.host }), t('review.web_runs.passive'), t('review.web_runs.scope', { host: webTarget.host }), t('review.web_runs.lifecycle')].map(item => <p key={item} className="flex gap-2 text-sm text-app-secondary"><Check className="mt-0.5 size-4 shrink-0 text-brand" />{item}</p>)}</div>
              <div className="space-y-2 rounded-xl border border-app-line bg-inset p-4"><p className="text-xs font-medium tracking-widest text-app-subtle uppercase">{t('review.skips')}</p>{[t('review.web_skips.attacks'), t('review.web_skips.login'), t('review.web_skips.hosts'), t('review.web_skips.pentest')].map(item => <p key={item} className="flex gap-2 text-sm text-app-muted"><X className="mt-0.5 size-4 shrink-0 text-app-subtle" />{item}</p>)}</div>
              <p className="flex items-start gap-3 rounded-xl border border-app-line bg-inset p-4 text-xs leading-5 text-app-muted"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-app-subtle" /><span>{t('review.web_authorization')}</span></p>
            </>}
          </CardContent></Card>
          {error && <p role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</p>}
        </div>}

        <div className="flex items-center justify-between gap-3 border-t border-app-line pt-5">
          <Button variant="ghost" onClick={() => step === 0 ? setKind(null) : setStep(step - 1)}><ArrowLeft /> {t('wizard.back')}</Button>
          {current === 'review'
            ? <Button onClick={() => void launch()} disabled={busy || !ready} className="bg-primary text-primary-foreground hover:bg-primary/90">{busy ? <LoaderCircle className="motion-safe:animate-spin" /> : batch ? <Layers3 /> : kind === 'web' ? <Globe2 /> : <SearchCheck />}{busy ? t('launch.queuing') : kind === 'web' ? t('launch.web') : kind === 'image' ? references.length > 1 ? t('launch.images', { total: references.length }) : t('launch.image') : codeMode === 'org' ? orgTotal ? t('launch.organization_count', { total: orgTotal }) : t('launch.organization') : chosenSources.length > 1 ? t('launch.repositories', { total: chosenSources.length }) : t('launch.code')}</Button>
            : <Button onClick={() => setStep(step + 1)} disabled={step === 0 && !ready} className="bg-primary text-primary-foreground hover:bg-primary/90">{t('wizard.continue')} <ArrowRight /></Button>}
        </div>
      </div>

      <ol className="order-first space-y-1 xl:order-none">{steps.map((item, index) => <li key={item.id}><button onClick={() => index <= step && setStep(index)} disabled={index > step} aria-current={index === step ? 'step' : undefined} className={`flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm transition ${index === step ? 'text-app-fg' : 'text-app-subtle'} ${index < step ? 'hover:bg-app-soft' : ''}`}><span className={`flex size-6 shrink-0 items-center justify-center rounded-full border font-mono text-xs ${index === step ? 'border-brand bg-primary/15 text-brand' : index < step ? 'border-brand/40 bg-brand/10 text-brand' : 'border-app-line'}`}>{index < step ? <Check className="size-3" /> : index + 1}</span>{t(item.label)}</button></li>)}</ol>
    </div>

    <SourceDialog open={pickSource} onOpenChange={setPickSource} selected={chosenSources.map(item => item.id)} onToggle={item => setChosenSources(previous => previous.some(entry => entry.id === item.id) ? previous.filter(entry => entry.id !== item.id) : [...previous, item])} onManageConnections={onManageConnections} />
  </div>
}

function Row({ label, value }: { label: string; value: string }) {
  return <div className="flex flex-col gap-1 border-b border-app-line pb-3 last:border-0 sm:flex-row sm:gap-4"><span className="w-28 shrink-0 text-xs text-app-subtle">{label}</span><span className="min-w-0 text-sm break-words text-app-secondary">{value}</span></div>
}

function SourceDialog({ open, onOpenChange, selected, onToggle, onManageConnections }: { open: boolean; onOpenChange: (open: boolean) => void; selected: string[]; onToggle: (source: Source) => void; onManageConnections: () => void }) {
  const { t } = useTranslation('analyses')
  const [connected, setConnected] = useState(true)
  const loaded = useCallback((data: SourcePage) => setConnected(Object.values(data.providers).some(item => item.configured)), [])
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className="max-w-xl">
    <DialogHeader><DialogTitle>{t('source.add')}</DialogTitle><DialogDescription>{t('source.dialog_description', { limit: BATCH_LIMIT })}</DialogDescription></DialogHeader>
    {open && <div className="max-h-[60vh] overflow-y-auto pr-1"><SourceSearch autoFocus onLoaded={loaded} render={item => { const on = selected.includes(item.id)
      return <button aria-pressed={on} onClick={() => onToggle(item)} className={`flex w-full items-center gap-3 rounded-xl border p-3 text-left transition ${on ? 'border-brand/60 bg-brand/10' : 'border-app-line bg-inset hover:border-brand/30'}`}><Code2 className="size-4 shrink-0 text-app-muted" /><span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{item.name}</span><span className="text-xs text-app-subtle">{item.provider.toUpperCase()} · {item.branch ?? t('source.default_branch')}{item.installation_id ? '' : ` · ${t('source.not_in_app_single')}`}</span></span>{on ? <Check className="size-4 text-brand" /> : item.private ? <LockKeyhole className="size-4 text-app-subtle" /> : null}</button> }} /></div>}
    {!connected && <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-app-line bg-inset p-4 text-sm"><span className="text-app-muted">{t('source.no_provider')}</span><Button variant="outline" onClick={onManageConnections} className="border-app-line bg-panel">{t('source.connect')}</Button></div>}
    <DialogFooter><span className="mr-auto text-xs text-app-subtle">{t('source.selected', { count: selected.length })}</span><Button onClick={() => onOpenChange(false)} className="bg-primary text-primary-foreground hover:bg-primary/90">{t('source.done')}</Button></DialogFooter>
  </DialogContent></Dialog>
}
