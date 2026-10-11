// Severity and state colours from the identity manual: Crítica solid critical with white text, Alta critical, Media
// attention (orange), Baja info, Info a muted outline. Always shown with its word, never colour alone.
export const SEVERITY_CLASS: Record<string, string> = {
  critical: 'border-transparent bg-danger-solid text-on-solid', high: 'border-danger-line bg-danger-soft text-danger',
  medium: 'border-attention-line bg-attention-soft text-attention', low: 'border-info-line bg-info-soft text-info',
  info: 'border-app-line text-app-muted',
}
export const severityClass = (severity: string) => SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info

// A state as coloured text with its border (outline badges): ok, failed, partial/due soon, running/queued.
export type StateTone = 'ok' | 'critical' | 'attention' | 'info' | 'neutral'
export const STATE_CLASS: Record<StateTone, string> = {
  ok: 'border-success-line text-success', critical: 'border-danger-line text-danger', attention: 'border-attention-line text-attention',
  info: 'border-info-line text-info', neutral: 'border-app-line text-app-muted',
}
