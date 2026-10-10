import { useTranslation } from 'react-i18next'
import { KeyFigure, KeyFigures } from '@/shared/ui/key-figures'
import type { FindingKpis } from '@/features/findings/finding-model'

// The figures above the findings, counted by the server over the pending work only: what is dismissed isn't work.
export function KpiTiles({ kpis }: { kpis: FindingKpis }) {
  const { t } = useTranslation('findings')
  return <KeyFigures>
    {kpis.has_sla && <Tile label={t('tiles.overdue')} value={kpis.overdue} tone={kpis.overdue ? 'rose' : 'muted'} hint={t('tiles.due_soon', { count: kpis.soon })} />}
    <Tile label={t('common:priority.act')} value={kpis.act} tone={kpis.act ? 'rose' : 'muted'} />
    <Tile label={t('common:priority.attend')} value={kpis.attend} tone={kpis.attend ? 'amber' : 'muted'} />
    <Tile label={t('tiles.critical')} value={kpis.critical} tone={kpis.critical ? 'rose' : 'muted'} />
    <Tile label={t('tiles.high')} value={kpis.high} tone={kpis.high ? 'orange' : 'muted'} />
    <Tile label={t('tiles.kev')} value={kpis.kev} tone={kpis.kev ? 'rose' : 'muted'} hint={t('tiles.kev_hint')} />
    <Tile label={t('tiles.fixable')} value={kpis.fixable} tone="teal"
      hint={`${kpis.only_excluded ? t('tiles.of_excluded', { count: kpis.active }) : t('tiles.of_pending', { count: kpis.active })}${kpis.dismissed ? ` · ${t('tiles.dismissed', { count: kpis.dismissed })}` : ''}`} />
  </KeyFigures>
}

function Tile({ label, value, tone, hint }: { label: string; value: number; tone: 'rose' | 'amber' | 'orange' | 'teal' | 'muted'; hint?: string }) {
  return <KeyFigure label={label} value={value} hint={hint} tone={({ rose: 'danger', amber: 'warning', orange: 'attention', teal: 'success', muted: 'neutral' } as const)[tone]} />
}
