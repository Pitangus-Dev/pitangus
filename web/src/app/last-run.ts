import type { RunRow } from '@/shared/lib/types'
import type { View } from '@/app/navigation'

// The kinds of run that are an analysis (the same as an asset's history); an advisory watch runs on its own.
const ANALYSES = new Set(['repository_scan', 'image_scan', 'dast_scan', 'pr_review', 'sarif_import'])
// Where "Last run" means something: the pages that show results, not settings or integrations.
export const LAST_RUN_VIEWS: ReadonlySet<View> = new Set<View>(['overview', 'findings', 'analyses'])

// The newest analysis of any kind, by its date: the list's order isn't relied on.
export function lastAnalysis(rows: RunRow[]): RunRow | undefined {
  let newest: RunRow | undefined
  let newestAt = -Infinity
  for (const row of rows) {
    const at = Date.parse(row.created_at)
    if (ANALYSES.has(row.type) && !Number.isNaN(at) && at > newestAt) { newest = row; newestAt = at }
  }
  return newest
}
