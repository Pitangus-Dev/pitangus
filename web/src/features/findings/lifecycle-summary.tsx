import { Trans, useTranslation } from 'react-i18next'
import type { LifecycleCounts } from '@/features/findings/finding-model'

// Where an asset (or a scope) stands: what is pending (and of it, from pull requests), fixed, dismissed and excluded.
export function LifecycleSummary({ counts }: { counts: LifecycleCounts }) {
  const { t } = useTranslation('findings')
  return <p className="text-sm text-app-muted">
    <Trans t={t} i18nKey="state.pending" count={counts.open} components={{ strong: <strong className="text-app-fg" /> }} />
    {counts.from_pr ? ` ${t('state.from_pr', { count: counts.from_pr })}` : ''} · <Trans t={t} i18nKey="state.fixed" count={counts.fixed} components={{ strong: <strong className="text-success" /> }} />
    {' · '}{t('state.suppressed', { count: counts.suppressed })}{counts.excluded ? ` · ${t('state.excluded', { count: counts.excluded })}` : ''}
  </p>
}
