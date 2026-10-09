import { useTranslation } from 'react-i18next'
import { Clock3, Flame, Wrench } from 'lucide-react'
import { Card, CardContent } from '@/shared/ui/card'
import type { FindingKpis } from '@/features/findings/finding-model'

// The figures above the findings, counted by the server over the pending work only: what is dismissed isn't work.
export function KpiTiles({ kpis }: { kpis: FindingKpis }) {
  const { t } = useTranslation('findings')
  return <div className={`grid gap-3 ${kpis.has_sla ? 'grid-cols-2 sm:grid-cols-4 xl:grid-cols-7' : 'sm:grid-cols-3 xl:grid-cols-6'}`}>
    {kpis.has_sla && <Tile label={t('tiles.overdue')} value={kpis.overdue} tone={kpis.overdue ? 'rose' : 'muted'} hint={t('tiles.due_soon', { count: kpis.soon })} icon={Clock3} />}
    <Tile label={t('common:priority.act')} value={kpis.act} tone={kpis.act ? 'rose' : 'muted'} icon={Flame} />
    <Tile label={t('common:priority.attend')} value={kpis.attend} tone={kpis.attend ? 'amber' : 'muted'} />
    <Tile label={t('tiles.critical')} value={kpis.critical} tone={kpis.critical ? 'rose' : 'muted'} />
    <Tile label={t('tiles.high')} value={kpis.high} tone={kpis.high ? 'orange' : 'muted'} />
    <Tile label={t('tiles.kev')} value={kpis.kev} tone={kpis.kev ? 'rose' : 'muted'} hint={t('tiles.kev_hint')} />
    <Tile label={t('tiles.fixable')} value={kpis.fixable} tone="teal" icon={Wrench}
      hint={`${kpis.only_excluded ? t('tiles.of_excluded', { count: kpis.active }) : t('tiles.of_pending', { count: kpis.active })}${kpis.dismissed ? ` · ${t('tiles.dismissed', { count: kpis.dismissed })}` : ''}`} />
  </div>
}

function Tile({ label, value, tone, hint, icon: Icon }: { label: string; value: number; tone: 'rose' | 'amber' | 'orange' | 'teal' | 'muted'; hint?: string; icon?: typeof Flame }) {
  const color = { rose: 'text-danger', amber: 'text-warning', orange: 'text-attention', teal: 'text-success', muted: 'text-app-fg' }[tone]
  return <Card className="border-app-line bg-panel"><CardContent className="flex items-start justify-between p-4"><div><div className={`text-2xl font-semibold tabular-nums ${color}`}>{value}</div><div className="mt-0.5 text-xs text-app-muted">{label}</div>{hint && <div className="text-[11px] text-app-subtle">{hint}</div>}</div>{Icon && <Icon className="size-4 text-app-subtle" />}</CardContent></Card>
}
