import { Trans, useTranslation } from 'react-i18next'
import type { LifecycleCounts } from '@/features/findings/finding-model'

// Where an asset (or a scope) stands: what is pending (and of it, from pull requests), unverified, fixed, dismissed and
// excluded. Every figure is one of the tabs' or the status filter's, so the header and the list always agree.
export function LifecycleSummary({ counts }: { counts: LifecycleCounts }) {
  const { t } = useTranslation('findings')
  return <p className="text-sm text-app-muted">
    <Trans t={t} i18nKey="state.pending" count={counts.open} components={{ strong: <strong className="text-app-fg" /> }} />
    {counts.from_pr ? ` ${t('state.from_pr', { count: counts.from_pr })}` : ''}{counts.unverified ? ` · ${t('state.unverified', { count: counts.unverified })}` : ''}
    {' · '}<Trans t={t} i18nKey="state.fixed" count={counts.fixed} components={{ strong: <strong className="text-success" /> }} />
    {' · '}{t('state.suppressed', { count: counts.suppressed })}{counts.excluded ? ` · ${t('state.excluded', { count: counts.excluded })}` : ''}
  </p>
}
