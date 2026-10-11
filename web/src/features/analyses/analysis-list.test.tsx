import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import i18n from '@/shared/i18n'
import { mockApi } from '@/shared/test/api'
import { renderWithQueries } from '@/shared/test/render'
import { AnalysisList } from '@/features/analyses/analysis-list'

describe('scan list', () => {
  it('the scan list names the run type and the tool', async () => {
    mockApi(call => {
      if (call.path.startsWith('/api/runs/page')) return { body: { items: [{ id: 'run-imp', type: 'sarif_import', status: 'completed', created_at: '2026-09-01T00:00:00Z',
        target: 'org/api', source: { name: 'org/api' }, trigger: { kind: 'import', tool: 'Semgrep', scope: 'full' }, summary: { candidates: 1 } }], total: 1, limit: 25, offset: 0 } }
      if (call.path.includes('batches')) return { body: { active: null, recent: [] } }
    })
    renderWithQueries(<AnalysisList refreshKey={0} onOpen={() => {}} onNew={() => {}} viewer={{ username: 'ana', admin: false }} />)

    expect(await screen.findByText(i18n.t('analyses:run_type.sarif_import'))).toBeTruthy()
    expect(screen.getByText(i18n.t('analyses:list.trigger_import', { tool: 'Semgrep' }))).toBeTruthy()
    expect(screen.queryByText('sarif_import')).toBeNull()
  })

  it("doesn't count findings of a run that is still going or that failed", async () => {
    const row = (id: string, status: string) => ({ id, type: 'dast_scan', status, created_at: '2026-10-10T00:00:00Z', target: id, source: { name: id }, summary: { candidates: 0 } })
    mockApi(call => {
      if (call.path.startsWith('/api/runs/page')) return { body: { items: [row('running.example', 'running'), row('failed.example', 'failed')], total: 2, limit: 25, offset: 0 } }
      if (call.path.includes('batches')) return { body: { active: null, recent: [] } }
    })
    renderWithQueries(<AnalysisList refreshKey={0} onOpen={() => {}} onNew={() => {}} viewer={{ username: 'ana', admin: false }} />)

    const running = (await screen.findByText('running.example')).closest('button') as HTMLElement
    expect(within(running).getByText(i18n.t('analyses:list.findings_pending'))).toBeTruthy()
    const failed = screen.getByText('failed.example').closest('button') as HTMLElement
    expect(within(failed).getByText(i18n.t('analyses:list.findings_none_failed'))).toBeTruthy()
    for (const item of [running, failed]) expect(within(item).queryByText('0')).toBeNull()
  })
})
