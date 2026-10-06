export type TriageStatus = 'open' | 'in_progress' | 'false_positive' | 'accepted' | 'fixed'
export type TriageEvent = { status: TriageStatus; reason?: string; note?: string; by: string; at: string; expires_at?: string | null; run_id?: string }
export type TriageState = { status: TriageStatus; reason?: string | null; note?: string | null; by?: string | null; at?: string | null; expires_at?: string | null; expired?: boolean; history?: TriageEvent[] }

// Catalog keys for each status label (common namespace).
export const TRIAGE_LABEL = {
  open: 'common:finding_status.open', in_progress: 'common:finding_status.in_progress', false_positive: 'common:finding_status.false_positive',
  accepted: 'common:finding_status.accepted', fixed: 'common:finding_status.fixed',
} as const satisfies Record<TriageStatus, string>
export const SUPPRESSED: TriageStatus[] = ['false_positive', 'accepted', 'fixed']
