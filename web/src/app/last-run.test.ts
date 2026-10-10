import { describe, expect, it } from 'vitest'
import { LAST_RUN_VIEWS, lastAnalysis } from '@/app/last-run'
import type { RunRow } from '@/shared/lib/types'

const row = (id: string, type: string, created_at: string): RunRow => ({ id, type, status: 'completed', created_at, summary: {} } as RunRow)

describe('the last run in the page header', () => {
  it('is the newest analysis of any kind, whatever order the list comes in', () => {
    // An older repository scan first used to win over every web scan after it.
    const rows = [row('repo', 'repository_scan', '2026-10-09T22:32:00Z'), row('web-1', 'dast_scan', '2026-10-10T15:42:20Z'),
      row('web-2', 'dast_scan', '2026-10-10T20:00:49Z'), row('watch', 'advisory_watch', '2026-10-10T23:00:00Z'), row('import', 'sarif_import', '2026-10-10T05:29:40Z')]
    expect(lastAnalysis(rows)?.id).toBe('web-2')
    expect(lastAnalysis([row('watch', 'advisory_watch', '2026-10-10T23:00:00Z')])).toBeUndefined()
    expect(lastAnalysis([])).toBeUndefined()
  })

  it('shows on the result pages only', () => {
    expect([...LAST_RUN_VIEWS].sort()).toEqual(['analyses', 'findings', 'overview'])
    expect(LAST_RUN_VIEWS.has('integrations')).toBe(false)
  })
})
