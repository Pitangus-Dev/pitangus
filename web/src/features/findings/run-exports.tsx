import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowDownToLine, ChevronDown, FileCheck2 } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Menu, MenuContent, MenuGroup, MenuItem, MenuTrigger } from '@/shared/ui/menu'
import { api, query } from '@/shared/api/http'
import type { FindingTab, RepositoryRun } from '@/features/findings/finding-model'

const RUN_EXPORTS: { label: string; items: [string, string][] }[] = [
  { label: 'export.compliance', items: [['export.sbom', 'sbom.cdx.json'], ['export.vex', 'vex.openvex.json']] },
  { label: 'export.data', items: [['export.markdown', 'report.md'], ['export.sarif', 'findings.sarif'], ['export.json', 'run.json'], ['export.jira', 'tickets.json']] },
]

// One asset's files (Hick's law: the usual report at hand, the other formats grouped in a menu): of a run, or of an
// asset's state in the tab shown (`status`).
export function RunExports({ run, status, onAudit }: { run: RepositoryRun; status: FindingTab; onAudit: () => void }) {
  const { t } = useTranslation('findings')
  const [error, setError] = useState('')
  const [downloading, setDownloading] = useState<string | null>(null)
  // The SBOM comes from a completed full scan (the latest one, in an asset's state); a PR review has none.
  const sbomAvailable = run.type === 'asset_state' || ((run.type === 'repository_scan' || run.type === 'image_scan') && run.status === 'completed')
  const exportFile = async (artifact: string) => {
    setError(''); setDownloading(artifact)
    try {
      const isState = run.type === 'asset_state'
      const path = isState
        ? `/api/assets/export?${query({ key: run.source?.id, status, artifact: artifact === 'run.json' ? 'record.json' : artifact })}`
        : artifact === 'run.json' ? `/api/runs/${run.id}` : `/api/runs/${run.id}/${artifact}`
      const name = (run.source?.name ?? t('export.file_fallback')).replace(/[^a-z0-9-]+/gi, '-').slice(0, 50) || t('export.file_fallback')
      await api.download(path, `${name}-${isState ? t('export.state_suffix') : run.id.slice(0, 8)}-${artifact}`)
    } catch (caught) { setError(caught instanceof Error ? caught.message : String(caught)) }
    finally { setDownloading(null) }
  }
  return <>
    <div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" disabled={downloading !== null} className="border-app-line bg-app-soft" onClick={() => void exportFile('report.pdf')}><ArrowDownToLine />{downloading === 'report.pdf' ? t('export.preparing') : t('export.pdf')}</Button>
      <Menu><MenuTrigger render={<Button variant="outline" size="sm" disabled={downloading !== null} className="border-app-line bg-app-soft" />}>{downloading && downloading !== 'report.pdf' ? t('export.preparing') : t('export.more')}<ChevronDown className="size-3.5" /></MenuTrigger>
        <MenuContent align="start"><MenuGroup label={t('export.audit_group')}><MenuItem onClick={onAudit}><FileCheck2 />{t('export.audit')}</MenuItem></MenuGroup>{RUN_EXPORTS.map(group => <MenuGroup key={group.label} label={t(group.label)}>{group.items.filter(([, artifact]) => artifact !== 'sbom.cdx.json' || sbomAvailable).map(([label, artifact]) => <MenuItem key={artifact} onClick={() => void exportFile(artifact)}>{t(label)}</MenuItem>)}</MenuGroup>)}</MenuContent></Menu></div>
    {error && <div role="alert" className="rounded-xl border border-danger-line bg-danger-soft px-4 py-3 text-sm text-danger">{t('export.error', { error })}</div>}
  </>
}
