import { useEffect, useState } from 'react'
import type { View } from '@/app/navigation'
import type { DomainTab } from '@/features/domains/domain-list'
import { readRoute } from '@/shared/lib/route'

// What the wizard starts from: a repository picked in Repositories (not in the address), or the domain and type of
// `#/new?domain=…&type=…` (a domain's "New scan" or "Import results").
export type WizardStart = { source: string | null; domain: string | null; type: string | null }
export type DomainRoute = { id: string; tab: DomainTab }

// Unknown or retired tabs (the old `access`, now part of the overview) open the overview.
export const domainTabOf = (tab: string | null): DomainTab => tab === 'findings' || tab === 'scans' || tab === 'scope' || tab === 'users' ? tab : 'overview'

export const wizardStartOf = (params: URLSearchParams): WizardStart => ({ source: null, domain: params.get('domain'), type: params.get('type') })
export const domainRouteOf = (params: URLSearchParams): DomainRoute => ({ id: params.get('id') ?? '', tab: domainTabOf(params.get('tab')) })

// The same object when the address names the same start, so a wizard in progress isn't remounted.
export const nextWizardStart = (current: WizardStart, params: URLSearchParams): WizardStart => {
  const next = wizardStartOf(params)
  return current.domain === next.domain && current.type === next.type ? current : next
}
const nextDomainRoute = (current: DomainRoute, params: URLSearchParams): DomainRoute => {
  const next = domainRouteOf(params)
  return current.id === next.id && current.tab === next.tab ? current : next
}

// The address leads: Back, Forward, a link or an edited address in the same tab restore the view and what it opens.
export function useRouteState() {
  const [view, setView] = useState<View>(() => (readRoute().view as View | null) ?? 'overview')
  const [selectedId, setSelectedId] = useState<string | null>(() => readRoute().params.get('run'))
  const [wizardStart, setWizardStart] = useState<WizardStart>(() => wizardStartOf(readRoute().params))
  const [domainRoute, setDomainRoute] = useState<DomainRoute>(() => domainRouteOf(readRoute().params))
  useEffect(() => {
    const sync = () => {
      const { view, params } = readRoute()
      if (!view) return
      setView(view as View); setSelectedId(params.get('run'))
      if (view === 'new') setWizardStart(current => nextWizardStart(current, params))
      if (view === 'domain') setDomainRoute(current => nextDomainRoute(current, params))
    }
    // hashchange too: a link or an edited address in the same tab changes the hash without always firing popstate.
    window.addEventListener('popstate', sync)
    window.addEventListener('hashchange', sync)
    return () => { window.removeEventListener('popstate', sync); window.removeEventListener('hashchange', sync) }
  }, [])
  return { view, setView, selectedId, setSelectedId, wizardStart, setWizardStart, domainRoute, setDomainRoute }
}
