import { useQuery, useQueryClient } from '@tanstack/react-query'
import { healthQuery, keys, runsQuery, domainsQuery } from '@/shared/api/queries'
import { useCallback, useEffect, useMemo, useRef, useState, Fragment } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { CaretRightIcon, ClockIcon, ListIcon, MagnifyingGlassIcon, MonitorIcon, MoonIcon, ScanIcon, SignOutIcon, SunIcon, XIcon } from '@phosphor-icons/react'
import { navigation, visibleNavigation, type View } from '@/app/navigation'
import { LAST_RUN_VIEWS, lastAnalysis } from '@/app/last-run'
import { CommandPalette } from '@/app/command-palette'
import { ShortcutsHelp } from '@/app/shortcuts-help'
import { dialogOpen, isMac, useShortcuts } from '@/shared/lib/shortcuts'
import { Keys } from '@/shared/ui/kbd'
import { BrandLockup } from '@/shared/ui/brand-mark'
import { BRAND } from '@/shared/lib/brand'
import { CodeSources } from '@/features/sources/code-sources'
import { DomainList, type DomainTab } from '@/features/domains/domain-list'
import type { Domain as DomainRow } from '@/features/domains/domains'
import { AnalysisList } from '@/features/analyses/analysis-list'
import { AnalysisWizard } from '@/features/analyses/analysis-wizard'
import { useToasts } from '@/features/analyses/use-toasts'
import { JiraBackgroundWork } from '@/features/integrations/jira-background'
import { Bone, TopProgress } from '@/shared/ui/loading'
import { UpdateNotice } from '@/app/update-notice'
import type { SessionActions, SessionUser } from '@/features/auth/session'
import { api } from '@/shared/api/http'
import { readRoute, writeRoute } from '@/shared/lib/route'
import { useRouteState } from '@/app/route-state'
import { Account } from '@/features/auth/account'
import { Dashboard } from '@/pages/Dashboard'
import { Findings } from '@/pages/Findings'
import { CveTracker } from '@/pages/CveTracker'
import { Users } from '@/pages/Users'
import { CoverageView } from '@/pages/Coverage'
import { Integrations } from '@/pages/Integrations'
import { PullRequests } from '@/pages/PullRequests'
import { ThreatModels } from '@/pages/ThreatModels'
import { Compliance } from '@/pages/Compliance'
import { Policies } from '@/pages/Policies'
import { Images } from '@/pages/Images'
import { Domain } from '@/pages/Domain'
import type { RunRow } from '@/shared/lib/types'
import { LocaleSwitch } from '@/shared/i18n/locale-switch'
import { formatDate } from '@/shared/i18n/format'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { Sheet, SheetClose, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from '@/shared/ui/sheet'

type Theme = 'system' | 'light' | 'dark'

const DESCRIPTION: Partial<Record<View, string>> = {
  overview: 'descriptions.overview', analyses: 'descriptions.analyses', repositories: 'descriptions.repositories', images: 'descriptions.images',
  domains: 'descriptions.domains', integrations: 'descriptions.integrations', account: 'descriptions.account', users: 'descriptions.users',
  pulls: 'descriptions.pulls', cves: 'descriptions.cves', compliance: 'descriptions.compliance', threats: 'descriptions.threats',
  policies: 'descriptions.policies',
}

function App({ user, session }: { user: SessionUser; session: SessionActions }) {
  const { t, i18n } = useTranslation('nav')
  const { view, setView, selectedId, setSelectedId, wizardStart, setWizardStart, domainRoute, setDomainRoute } = useRouteState()
  const runsResult = useQuery(runsQuery())
  const health = useQuery(healthQuery())
  const version = health.data?.version
  const rows = useMemo(() => runsResult.data ?? [], [runsResult.data])
  const queryClient = useQueryClient()
  const [detail, setDetail] = useState<RunRow | null>(null)
  useEffect(() => { if (!readRoute().view) writeRoute(view, {}, { replace: true }) }, [view])
  // Cada vista empieza arriba: sin esto hereda el scroll de la anterior (p. ej. el CVE tracker abría al pie).
  useEffect(() => { window.scrollTo({ top: 0 }) }, [view])
  const [error, setError] = useState<string | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  // The domain page's host follows its section in the header crumb (the same cached list the page reads).
  const domainList = useQuery({ ...domainsQuery(), enabled: view === 'domain' })
  const domainHost = view === 'domain' ? domainList.data?.items.find(item => item.id === domainRoute.id)?.host : undefined
  const toasts = useToasts()
  // Aviso al terminar un análisis: se compara con el estado anterior de cada fila (el sondeo lo hace la consulta).
  const previous = useRef<Map<string, string>>(new Map())
  useEffect(() => {
    for (const row of rows) {
      const before = previous.current.get(row.id)
      if ((before === 'queued' || before === 'running') && row.status !== 'queued' && row.status !== 'running') {
        const name = row.type === 'dast_scan' ? row.source?.name ?? row.target : row.type === 'repository_scan' ? row.source?.name ?? t('toast.repository') : row.type === 'image_scan' ? row.target ?? t('toast.image') : row.target
        const count = row.summary.candidates ?? 0, severities = row.summary.severities
        toasts.push(row.status === 'failed' ? 'error' : 'ok', row.status === 'failed'
          ? t('toast.failed', { name })
          : severities
            ? t('toast.done_severities', { name, count, critical: severities.critical ?? 0, high: severities.high ?? 0 })
            : t('toast.done', { name, count }))
        if (detail?.id === row.id) void openRun(row.id, 'findings')
      }
    }
    previous.current = new Map(rows.map(row => [row.id, row.status]))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows])
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('pitangus-theme')
    return saved === 'light' || saved === 'system' ? saved : 'dark'
  })
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const apply = () => {
      const dark = theme === 'dark' || (theme === 'system' && media.matches)
      document.documentElement.classList.toggle('dark', dark)
    }
    apply()
    media.addEventListener('change', apply)
    localStorage.setItem('pitangus-theme', theme)
    return () => media.removeEventListener('change', apply)
  }, [theme])

  const refresh = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: keys.runs })
    return queryClient.getQueryData<RunRow[]>(keys.runs) ?? []
  }, [queryClient])
  useEffect(() => { if (runsResult.error) setError(runsResult.error instanceof Error ? runsResult.error.message : String(runsResult.error)) }, [runsResult.error])
  const latest = useMemo(() => lastAnalysis(rows), [rows])
  const navLabel = navigation.flatMap(group => group.items).find(item => item.id === view)?.label
  const currentTitle = view === 'new' ? t('items.new') : view === 'domain' ? t('items.domains') : view === 'account' ? t('items.account') : navLabel ? t(navLabel) : t('items.overview')

  const openRun = useCallback(async (id: string, nextView: View = 'findings') => {
    setSelectedId(id)
    setView(nextView)
    writeRoute(nextView, { run: id })
    try {
      const run = await api.get<RunRow>(`/api/runs/${encodeURIComponent(id)}`)
      setDetail(run)
      setError(null)
      return run
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
  }, [setSelectedId, setView])
  // Entrar en Hallazgos desde el menú muestra el estado actual; abrir una ejecución concreta pasa por openRun.
  const selectView = (next: View) => { if (next === 'new') setWizardStart({ source: null, domain: null, type: null }); if (next === 'findings') setSelectedId(null); setView(next); setMobileOpen(false); writeRoute(next) }
  // Un CVE concreto del Resumen: la URL lleva su id (lo lee el tracker al montarse) y la vista cambia a la vez.
  const openTracker = (id?: string) => { if (!id) return selectView('cves'); writeRoute('cves', { id }); setView('cves'); setMobileOpen(false) }
  // The images built from a repository (from Repositories), and an image's findings (from Images).
  const openImages = (repository: { key: string; name: string }) => { writeRoute('images', { repo: repository.key, name: repository.name }); setView('images'); setMobileOpen(false) }
  const openAssetFindings = (key: string) => { setSelectedId(null); writeRoute('findings', { repo: key }); setView('findings'); setMobileOpen(false) }
  const scanSource = (id: string) => { setWizardStart({ source: id, domain: null, type: null }); setView('new'); setMobileOpen(false) }
  const openDomain = (domain: { id: string }, tab: DomainTab = 'overview') => { setDomainRoute({ id: domain.id, tab }); setView('domain'); writeRoute('domain', { id: domain.id, tab: tab === 'overview' ? null : tab }) }
  const domainTab = (tab: DomainTab) => { setDomainRoute(current => ({ ...current, tab })); writeRoute('domain', { id: domainRoute.id, tab: tab === 'overview' ? null : tab }, { replace: true }) }
  const scanDomain = (domain: DomainRow) => { setWizardStart({ source: null, domain: domain.id, type: 'web' }); setView('new'); writeRoute('new', { domain: domain.id, type: 'web' }) }
  const importResults = () => { setWizardStart({ source: null, domain: null, type: 'import' }); setView('new'); writeRoute('new', { type: 'import' }) }
  const completedRepositoryScan = async (id: string) => { await refresh(); await openRun(id, 'findings') }

  // El asistente vive dentro de Análisis: la sección sigue marcada mientras se crea una ejecución.
  const activeNav: View = view === 'new' ? 'analyses' : view === 'domain' ? 'domains' : view
  const admin = user.role === 'admin'
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [addDomainRequest, setAddDomainRequest] = useState(0)
  // A new key remounts the list, which reads `add` from the address and opens its form.
  const addDomain = () => { setAddDomainRequest(count => count + 1); setView('domains'); setMobileOpen(false); writeRoute('domains', { add: '1' }) }
  const openPalette = () => { setMobileOpen(false); setPaletteOpen(true) }
  useShortcuts({
    // ⌘K closes the palette too, but doesn't open it over another dialog.
    palette: () => setPaletteOpen(open => open ? false : !dialogOpen()),
    help: () => setHelpOpen(true),
    create: () => selectView('new'),
    go: letter => {
      const item = visibleNavigation(admin).flatMap(group => group.items).find(entry => entry.go === letter)
      if (item) selectView(item.id)
      return !!item
    },
  })
  const paletteKeys = [isMac() ? '⌘' : 'Ctrl', 'K']
  const search = <button type="button" onClick={openPalette} aria-keyshortcuts={isMac() ? 'Meta+K' : 'Control+K'}
    className="flex min-h-8 w-full items-center gap-2 rounded-lg border border-chrome-line bg-chrome-raised px-3 py-1.5 text-left text-sm text-on-chrome-muted transition hover:bg-chrome-line hover:text-on-chrome">
    <MagnifyingGlassIcon aria-hidden className="size-4" /><span className="flex-1">{t('palette.trigger')}</span><Keys keys={paletteKeys} className="max-lg:hidden [&_kbd]:border-chrome-line [&_kbd]:text-on-chrome-muted" />
  </button>
  const nav = <nav aria-label={t('main')} className="space-y-5">{visibleNavigation(admin).map(group => {
    const id = `nav-${group.id}`
    return <div key={group.id} role="group" aria-labelledby={id} className="space-y-1">
      <p id={id} className="px-3 pb-1 text-xs font-medium text-on-chrome-muted">{t(group.label)}</p>
      {group.items.map(item => <button key={item.id} onClick={() => selectView(item.id)} title={t('shortcuts.go_hint', { key: item.go.toUpperCase() })} aria-current={activeNav === item.id ? 'page' : undefined} className={`flex w-full items-center gap-3 rounded-lg px-3 py-1.5 text-left text-sm transition ${activeNav === item.id ? 'bg-chrome-raised font-medium text-chrome-active' : 'text-on-chrome hover:bg-chrome-raised'}`}><item.icon aria-hidden className="size-5" />{t(item.label)}</button>)}
    </div>
  })}</nav>

  const role = user.role === 'admin' ? t('auth:role.admin') : t('auth:role.member')
  const userCard = <div className="space-y-1 border-t border-chrome-line pt-3">
    <button onClick={() => selectView('account')} aria-current={view === 'account' ? 'page' : undefined} className={`flex w-full items-center gap-3 rounded-lg p-1 text-left transition hover:bg-chrome-raised ${view === 'account' ? 'bg-chrome-raised text-chrome-active' : 'text-on-chrome'}`}>
      <span aria-hidden className="grid size-8 shrink-0 place-items-center rounded-md border border-chrome-line bg-chrome-raised text-xs font-semibold text-on-chrome">{(Array.from(user.display_name)[0] ?? '').toUpperCase()}</span>
      <span className="min-w-0"><span className="block truncate text-sm font-medium">{user.display_name}</span><span className="block truncate text-xs text-on-chrome-muted">{user.totp_enabled ? role : t('role_without_2fa', { role })}</span></span>
      {!user.totp_enabled && <span role="img" aria-label={t('two_factor_off')} className="ml-auto size-2 shrink-0 rounded-full bg-attention" />}
    </button>
    <button type="button" onClick={() => void session.logout()} className="flex min-h-8 w-full items-center gap-3 rounded-lg px-3 py-1.5 text-left text-sm text-on-chrome-muted transition hover:bg-chrome-raised hover:text-on-chrome"><SignOutIcon aria-hidden className="size-4" />{t('auth:sign_out')}</button>
  </div>

  const renderMain = () => {
    if (view === 'new') {
      // `api` is the old address of what is now one web scan for sites and APIs.
      const type = wizardStart.type === 'api' ? 'web' : wizardStart.type === 'code' || wizardStart.type === 'image' || wizardStart.type === 'web' || wizardStart.type === 'import' ? wizardStart.type : null
      return <AnalysisWizard key={wizardStart.source ?? `${wizardStart.domain ?? ''}:${type ?? 'new'}`} initialSourceId={wizardStart.source} initialDomainId={wizardStart.domain} initialKind={type} isAdmin={user.role === 'admin'}
        onBatchStarted={() => selectView('analyses')} onComplete={completedRepositoryScan} onScheduled={id => openDomain({ id })} onManageConnections={() => selectView('integrations')} onCancel={() => selectView('analyses')} />
    }
    if (view === 'analyses') return <AnalysisList refreshKey={rows.length * 1000 + rows.filter(row => row.status === 'running' || row.status === 'queued').length} onOpen={id => openRun(id, 'findings')} onNew={() => selectView('new')} viewer={{ username: user.username, admin: user.role === 'admin' }} />
    if (view === 'repositories') return <CodeSources runs={rows} onScan={scanSource} onImages={openImages} canManage={user.role === 'admin'} />
    if (view === 'images') return <Images key={readRoute().params.get('repo') ?? 'all'} admin={user.role === 'admin'} onOpenFindings={openAssetFindings} onNew={() => selectView('new')} />
    if (view === 'domains') return <DomainList key={addDomainRequest} admin={user.role === 'admin'} onOpenDomain={openDomain} onNewScan={scanDomain} />
    if (view === 'domain') return <Domain key={domainRoute.id} domainId={domainRoute.id} tab={domainRoute.tab} onTab={domainTab} user={user} onBack={() => selectView('domains')}
      onNewScan={scanDomain} onOpenRun={id => openRun(id, 'findings')} onImport={importResults} onOpenPolicies={() => selectView('policies')} />
    if (view === 'overview') return <Dashboard onOpenRun={id => openRun(id, 'findings')} onNew={() => selectView('new')} onNavigate={view => selectView(view as View)} onTracker={openTracker} />
    if (view === 'threats') return <ThreatModels user={user} onOpenRun={id => openRun(id, 'findings')} />
    if (view === 'cves') return <CveTracker onNew={() => selectView('new')} />
    if (view === 'compliance') return <Compliance user={user} onNew={() => selectView('new')} />
    if (view === 'pulls') return <PullRequests user={user} onOpenRun={id => openRun(id, 'findings')} />
    if (view === 'findings') return <Findings key={selectedId ?? 'current'} user={user} requestedRun={selectedId} onNew={() => selectView('new')} onOpenPolicies={() => selectView('policies')} />
    if (view === 'policies') return <Policies user={user} />
    if (view === 'coverage') return <CoverageView />
    if (view === 'account') return <Account user={user} onChanged={session.reload} />
    if (view === 'users' && user.role === 'admin') return <Users me={user} />
    if (view === 'integrations') return <Integrations user={user} />
    return <Dashboard onOpenRun={id => openRun(id, 'findings')} onNew={() => selectView('new')} onNavigate={view => selectView(view as View)} onTracker={openTracker} />
  }

  return <div className="min-h-screen bg-app text-app-fg"><TopProgress /><div className="flex min-h-screen">
    <aside data-chrome className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col overflow-y-auto border-r border-chrome-line bg-chrome px-4 py-6 lg:flex"><div className="mb-5 px-2"><BrandLockup chrome /></div><div className="mb-5">{search}</div>{nav}<div className="mt-auto">{userCard}</div></aside>
    <div className="min-w-0 flex-1"><header className="sticky top-0 z-20 flex h-16 items-center justify-between gap-2 border-b border-app-line bg-app px-4 sm:px-8"><div className="flex min-w-0 items-center gap-3"><Sheet open={mobileOpen} onOpenChange={setMobileOpen}><SheetTrigger render={<Button aria-label={t('open_navigation')} variant="ghost" size="icon" className="lg:hidden" />}><ListIcon /></SheetTrigger><SheetContent side="left" showCloseButton={false} data-chrome className="w-72 overflow-y-auto border-chrome-line bg-chrome text-on-chrome"><SheetHeader className="flex-row items-center justify-between"><SheetTitle className="text-left"><BrandLockup size={32} chrome /></SheetTitle><SheetClose className="grid size-8 place-items-center rounded-lg text-on-chrome-muted transition hover:bg-chrome-raised hover:text-on-chrome"><XIcon aria-hidden className="size-4" /><span className="sr-only">{t('common:actions.close')}</span></SheetClose></SheetHeader><div className="space-y-6 px-3 pb-6">{search}{nav}{userCard}</div></SheetContent></Sheet><span className="hidden text-sm text-app-muted sm:inline">{t('workspace')}</span><CaretRightIcon className="hidden size-3 text-app-subtle sm:block" />{view === 'domain'
        ? <nav aria-label={t('breadcrumb')} className="flex min-w-0 items-center gap-1.5 text-sm"><button type="button" onClick={() => selectView('domains')} className="min-h-6 min-w-0 truncate text-app-muted underline-offset-2 hover:text-app-fg hover:underline">{currentTitle}</button>{domainHost && <><CaretRightIcon aria-hidden className="size-3 shrink-0 text-app-subtle max-sm:hidden" /><span aria-current="page" className="truncate font-medium max-sm:hidden">{domainHost}</span></>}</nav>
        : <span className="hidden text-sm font-medium sm:inline">{currentTitle}</span>}</div><div className="flex shrink-0 items-center gap-2 sm:gap-3"><JiraBackgroundWork onNotice={toasts.push} /><LocaleSwitch /><Select value={theme} onValueChange={value => setTheme(value as Theme)}><SelectTrigger aria-label={t('theme.label')} size="sm" className="border-input bg-card text-app-secondary sm:min-w-32">{theme === 'dark' ? <MoonIcon className="size-3.5" /> : theme === 'light' ? <SunIcon className="size-3.5" /> : <MonitorIcon className="size-3.5" />}<span className="hidden min-w-0 flex-1 text-left sm:block">{theme === 'system' ? t('theme.system') : theme === 'light' ? t('theme.light') : t('theme.dark')}</span></SelectTrigger><SelectContent align="end" className="border border-app-line bg-panel p-1 text-app-fg shadow-md"><SelectItem value="system">{t('theme.system')}</SelectItem><SelectItem value="light">{t('theme.light')}</SelectItem><SelectItem value="dark">{t('theme.dark')}</SelectItem></SelectContent></Select>{health.isPending ? <Bone className="hidden h-5 w-32 sm:block" /> : version && <Badge variant="outline" className="hidden border-app-line text-app-muted sm:inline-flex">{t('edition', { version })}</Badge>}<Button aria-label={t('items.new')} onClick={() => selectView('new')}><ScanIcon /><span className="hidden sm:inline">{t('items.new')}</span></Button></div></header>
    <main className="max-w-[1600px] space-y-6 px-4 py-6 sm:px-8 sm:py-8">{view !== 'domain' && view !== 'domains' && <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><div><h1 className="text-2xl font-semibold tracking-tight">{currentTitle}</h1>{view !== 'new' && <p className="mt-1 max-w-2xl text-sm text-app-muted">{t(DESCRIPTION[view] ?? 'descriptions.default')}</p>}</div>{latest && LAST_RUN_VIEWS.has(view) && <div className="flex items-center gap-2 text-xs text-app-subtle"><ClockIcon className="size-3.5" />{t('last_run', { date: formatDate(latest.created_at) })}</div>}</div>}
      {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{error}</div>}
      {/* Server text is fetched in the reader's language: remount views when it changes. */}
      <Fragment key={i18n.language}>{renderMain()}</Fragment>
      <footer className="border-t border-app-line pt-5 text-xs text-app-subtle"><Trans t={t} i18nKey="footer" values={{ name: BRAND.name }} components={{
        license: <a href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noopener noreferrer" className="underline-offset-2 hover:underline" />,
        source: <a href={BRAND.repo} target="_blank" rel="noopener noreferrer" className="underline-offset-2 hover:underline" />,
      }} /></footer>
    </main></div>
  </div>{toasts.view}<UpdateNotice />
    <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} admin={admin} onView={selectView} onImport={importResults} onAddDomain={addDomain}
      onHelp={() => setHelpOpen(true)} onOpenRun={id => void openRun(id, 'findings')} onOpenDomain={id => openDomain({ id })} onOpenAsset={openAssetFindings} />
    <ShortcutsHelp open={helpOpen} onOpenChange={setHelpOpen} admin={admin} />
  </div>
}

export default App
