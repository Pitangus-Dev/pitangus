import { useTranslation } from 'react-i18next'
import type { FindingTab, LifecycleCounts } from '@/features/findings/finding-model'

// The Findings tabs with how many each holds (counted by the server, so they change as soon as something is triaged).
// "Excluded" only shows when there is something under excluded paths.
export function FindingTabs({ tab, counts, onChange }: { tab: FindingTab; counts: LifecycleCounts | null | undefined; onChange: (tab: FindingTab) => void }) {
  const { t } = useTranslation('findings')
  const tabs: [FindingTab, string, number | null][] = [
    ['open', t('page.tabs.open'), counts ? counts.open + counts.suppressed : null], ['fixed', t('page.tabs.fixed'), counts ? counts.fixed : null],
    ['excluded', t('page.tabs.excluded'), counts ? counts.excluded ?? 0 : null],
    ['all', t('common:state.all'), counts ? counts.open + counts.suppressed + counts.fixed + (counts.excluded ?? 0) : null]]
  return <div className="flex flex-wrap gap-1.5">{tabs.filter(([key]) => key !== 'excluded' || tab === 'excluded' || (counts?.excluded ?? 0) > 0).map(([key, text, count]) =>
    <button key={key} type="button" aria-pressed={tab === key} onClick={() => onChange(key)} className={`rounded-lg border px-3 py-1.5 text-sm ${tab === key ? 'border-brand/50 bg-brand/10 text-brand' : 'border-app-line bg-app-soft text-app-muted'}`}>
      {text}{count !== null ? ` · ${count}` : ''}</button>)}</div>
}
