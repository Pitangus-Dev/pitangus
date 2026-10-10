import type { TFunction } from 'i18next'
import type { components } from '@/shared/api/schema'
import type { Sla } from '@/features/findings/sla'
import type { FixGuide, Verification } from '@/features/findings/fix-guide'
import type { TicketLink } from '@/features/integrations/jira-export'
import { SUPPRESSED, type TriageState, type TriageStatus } from '@/features/findings/triage-status'
import type { RunTrigger } from '@/shared/lib/types'

export type Priority = { action: 'act' | 'attend' | 'track'; factors: string[] }
export type Package = { ecosystem: string; name: string; version: string; fixed_version: string | null; introduced: string | null; dev?: boolean; direct?: boolean | null }
export type Advisory = { id: string; aliases: string[]; summary: string; details: string; cvss_vector: string | null; cvss_score: number | null; published: string | null; modified: string | null; references: string[] }
// Where an advisory comes from and its license (pitangus/modules/intel/data_sources.py): attributed wherever it is shown.
export type AdvisorySource = { id: string; name: string; short?: string; url: string; license: string; terms: 'open' | 'attribution' | 'share-alike' | 'non-commercial' | 'unclear' }
export type Lifecycle = { status: 'open' | 'fixed' | 'excluded'; excluded?: { pattern: string | null; reason?: string; at: string } | null; origin?: { kind: 'scan' | 'pr' | 'advisory' | 'import'; pr?: number; branch?: string; merged?: boolean; tool?: string | null }; first_seen?: string; last_seen?: string; fixed?: { at: string; how: string; auto: boolean } | null; reopened_at?: string | null }
// Findings of several assets (`asset_scope`) name their asset; the scope counts each asset's work and the tiles.
export type ScopeAssetRef = components['schemas']['ScopeAssetRef']
export type ScopeAsset = components['schemas']['ScopeAssetCounts']
export type FindingKpis = components['schemas']['FindingKpis']
export type LifecycleCounts = Pick<components['schemas']['LifecycleCounts'], 'open' | 'fixed' | 'suppressed' | 'from_pr'> & { excluded?: number }
export type RepositoryFinding = { finding_id: string; fingerprint: string; scanner: string; tool?: string; also_detected_by?: string[]; related_rules?: string[]; framework?: string; rule_id: string; title: string; path: string; line: number; severity: string; confidence: number; verdict: string; cwe: number[]; cve: string[]; ghsa: string[]; owasp: string[]; reason: string; remediation: string; package?: Package | null; advisory?: Advisory | null; kev?: { date_added: string | null; due_date: string | null; ransomware: boolean; name: string | null } | null; epss?: { score: number; percentile: number } | null; priority?: Priority; triage?: TriageState; ticket?: TicketLink; lifecycle?: Lifecycle; source?: AdvisorySource | null; fix?: FixGuide | null; verification?: Verification | null; sla?: Sla | null; malicious?: boolean; asset?: ScopeAssetRef }
export type ScanStep = { id: string; name: string; status: string; detail: string }
export type PullReview = { baseline_run: string | null; gate: string; verdict: { state: 'success' | 'failure'; description: string; blocking: number }; delivery: { comment?: string; status?: string } }
export type RepositoryRun = { id: string; type?: string; trigger?: RunTrigger; pull_request?: { number: number; title: string; url: string; author: string; head_sha: string; head_ref: string; base_ref: string }; review?: PullReview; status: string; created_at: string; context?: string; progress?: { at: string; level: 'info' | 'ok' | 'warn' | 'error'; message: string }[]; started_at?: string; finished_at?: string; source?: { id?: string; uid?: string | null; name: string; provider: string; sha256?: string; files?: number; branch?: string; commit?: string; image?: { reference: string; resolved_digest?: string | null; os?: string | null; user?: string } }; summary: { agreement?: { both: number; only_trivy: number; only_grype: number }; files?: number; dependencies?: number; candidates?: number; sast?: number; secrets?: number; sca?: number; severities?: Record<string, number>; priorities?: Record<string, number>; kev?: number; fixable?: number; triage?: Record<TriageStatus, number>; actionable?: number; preexisting?: number; changed_files?: number; lifecycle?: LifecycleCounts; kpis?: FindingKpis }; steps?: ScanStep[]; findings?: RepositoryFinding[] }
// The Findings tabs: the asset state's (or the scope's) open, fixed, excluded or every finding.
export type FindingTab = 'open' | 'fixed' | 'excluded' | 'all'

export const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
export const ACTION_ORDER: Record<string, number> = { act: 0, attend: 1, track: 2 }
// Catalog keys by value; unknown values are shown as they come.
export const SEVERITY_LABEL: Record<string, string> = { critical: 'common:severity.critical', high: 'common:severity.high', medium: 'common:severity.medium', low: 'common:severity.low', info: 'common:severity.info' }
export const ACTION_LABEL: Record<string, string> = { act: 'common:priority.act', attend: 'common:priority.attend', track: 'common:priority.track' }
export const SCANNER_LABEL: Record<string, string> = { sca: 'scanner.sca', sast: 'scanner.sast', secrets: 'scanner.secrets', iac: 'scanner.iac', cicd: 'scanner.cicd', dast: 'scanner.dast' }
export const labelOf = (t: TFunction, keys: Record<string, string>, value: string) => keys[value] ? t(keys[value]) : value
const TOOL_NAME: Record<string, string> = { trivy: 'Trivy', gitleaks: 'Gitleaks', opengrep: 'Opengrep', grype: 'Grype', 'osv-scanner': 'OSV-Scanner', checkov: 'Checkov', zizmor: 'zizmor' }
export const toolName = (t: TFunction, tool: string) => tool === 'pitangus' ? t('findings:tool.pitangus') : TOOL_NAME[tool] ?? tool
// The engine and, when another one confirmed it, that one too: "Trivy + Grype".
export const toolsOf = (t: TFunction, finding: { tool?: string; also_detected_by?: string[] }) => [finding.tool, ...(finding.also_detected_by ?? [])].filter(Boolean).map(tool => toolName(t, tool as string)).join(' + ')
export const severityClass = (severity: string) => ({
  critical: 'border-transparent bg-danger-solid text-on-solid', high: 'border-attention-line bg-attention-soft text-attention',
  medium: 'border-warning-line bg-warning-soft text-warning', low: 'border-info-line bg-info-soft text-info',
}[severity] ?? 'border-app-line text-app-muted')
export const actionClass = (action: string) => ({
  act: 'border-transparent bg-danger-solid text-on-solid', attend: 'border-warning-line text-warning', track: 'border-app-line text-app-subtle',
}[action] ?? 'border-app-line text-app-subtle')

// An asset's state as a run id (findings.registry.VIEW_PREFIX): what its findings are triaged and re-verified against.
export const stateId = (key: string) => `asset:${key}`
// A finding's identity in the table: its fingerprint and, with several assets, its asset (the same fingerprint can be
// in two of them).
export const idOf = (finding: RepositoryFinding) => finding.asset ? `${finding.asset.key}|${finding.fingerprint}` : finding.fingerprint
// Fixed by a scan (the registry no longer sees it) counts the same as fixed by hand.
export const statusOf = (finding: RepositoryFinding): TriageStatus => finding.lifecycle?.status === 'fixed' ? 'fixed' : finding.triage?.status ?? 'open'
// Whether a finding shows under a status view: 'all', 'active' (not dismissed) or one status.
export const inView = (finding: RepositoryFinding, view: string) => view === 'all' || (view === 'active' ? !SUPPRESSED.includes(statusOf(finding)) : statusOf(finding) === view)
// Still work to do: only these can get a Jira issue.
export const isPending = (finding: RepositoryFinding) => finding.lifecycle?.status !== 'excluded' && !SUPPRESSED.includes(statusOf(finding))

// Tolerant version comparison, to pick the fix that closes every advisory of a package.
const versionKey = (value: string) => value.replace(/^v/i, '').split(/[.+-]/).map(part => { const number = parseInt(part, 10); return Number.isNaN(number) ? 0 : number })
const newer = (left: string, right: string) => { const a = versionKey(left), b = versionKey(right); for (let index = 0; index < Math.max(a.length, b.length); index++) { const diff = (a[index] ?? 0) - (b[index] ?? 0); if (diff) return diff > 0 } return false }
const worst = (findings: RepositoryFinding[]) => findings.reduce((best, item) => SEVERITY_ORDER[item.severity] < SEVERITY_ORDER[best] ? item.severity : best, 'info')
const urgent = (findings: RepositoryFinding[]) => findings.reduce((best, item) => (ACTION_ORDER[item.priority?.action ?? 'track'] ?? 3) < (ACTION_ORDER[best] ?? 3) ? item.priority?.action ?? 'track' : best, 'track')

export type Group = { key: string; label: string; meta: string; scanner: string; findings: RepositoryFinding[]; severity: string; action: string; fix: string | null; epss: number | null; kev: boolean; sla: Sla | null }

// A package with three advisories is one piece of remediation work: grouped, saying the version that closes them all.
export function groupFindings(findings: RepositoryFinding[], t: TFunction): Group[] {
  const groups = new Map<string, RepositoryFinding[]>()
  for (const finding of findings) {
    const key = `${finding.asset ? `${finding.asset.key}|` : ''}${finding.package ? `${finding.package.ecosystem}:${finding.package.name}@${finding.package.version}` : `${finding.scanner}:${finding.finding_id}`}`
    groups.set(key, [...(groups.get(key) ?? []), finding])
  }
  return Array.from(groups.entries()).map(([key, items]) => {
    const pkg = items[0].package
    const fix = pkg ? items.reduce<string | null>((best, item) => item.package?.fixed_version && (!best || newer(item.package.fixed_version, best)) ? item.package.fixed_version : best, null) : null
    const epss = items.reduce<number | null>((best, item) => item.epss && (best === null || item.epss.score > best) ? item.epss.score : best, null)
    // The group's due date is the most pressing of its advisories'.
    const sla = items.reduce<Sla | null>((best, item) => item.sla && (!best || item.sla.days_left < best.days_left) ? item.sla : best, null)
    return { key, findings: items, scanner: items[0].scanner, severity: worst(items), action: urgent(items), fix, epss, kev: items.some(item => item.kev), sla,
      label: pkg ? `${pkg.name} ${pkg.version}` : items[0].title,
      meta: pkg ? [t('findings:group.advisories', { count: items.length }), pkg.ecosystem, ...(pkg.dev ? [t('findings:group.dev')] : pkg.direct === false ? [t('findings:group.transitive')] : []),
        fix ? t('findings:group.upgrade', { version: fix }) : t('findings:group.no_fix')].join(' · ') : `${items[0].path}:${items[0].line}` }
  }).sort((left, right) => (ACTION_ORDER[left.action] - ACTION_ORDER[right.action]) || (SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]) || left.label.localeCompare(right.label))
}
