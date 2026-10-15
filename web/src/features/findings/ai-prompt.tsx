import { useEffect, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { CheckIcon, CopyIcon } from '@phosphor-icons/react'
import { Button } from '@/shared/ui/button'
import { findingCodeQuery, fixPromptQuery } from '@/shared/api/queries'
import type { components } from '@/shared/api/schema'

// "Fix it with your own AI": the finding as a prompt (rule, place, code, fix; never a secret's value) to paste into
// Claude, Cursor or Copilot. The server's prompt has no code (Pitangus stores none): the code the reader opened, with
// its secrets masked, goes in here, in their browser. Pitangus sends it nowhere.
export function AiPrompt({ runId, fingerprint, withCode = false }: { runId: string; fingerprint: string; withCode?: boolean }) {
  const { t } = useTranslation('findings')
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const timer = useRef<number | undefined>(undefined)
  const alert = useId()
  const { data: built, isError } = useQuery(fixPromptQuery(runId, fingerprint))
  const { data: opened } = useQuery({ ...findingCodeQuery(runId, fingerprint), enabled: withCode })
  useEffect(() => () => window.clearTimeout(timer.current), [])
  if (isError) return null
  const code = withCode ? promptCode(opened, t('code.masked_line')) : null
  const data = built && { prompt: code ? `${built.before}\n\n${built.heading}\n\`\`\`${built.language}\n${code}\n\`\`\`\n\n${built.after}\n` : built.prompt }
  const copy = () => {
    if (!data) return
    navigator.clipboard.writeText(data.prompt)
      .then(() => { setState('copied'); window.clearTimeout(timer.current); timer.current = window.setTimeout(() => setState('idle'), 2000) })
      .catch(() => setState('failed'))
  }
  return <div className="mt-4 space-y-2 border-t border-app-line pt-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p className="min-w-0 grow basis-64 text-xs text-app-muted">{t('ai_prompt.help')}</p>
      <Button size="sm" variant="outline" aria-disabled={!data} onClick={copy} className="border-input bg-card aria-disabled:opacity-60">
        {state === 'copied' ? <CheckIcon className="text-success" /> : <CopyIcon />}{state === 'copied' ? t('ai_prompt.copied') : t('ai_prompt.copy')}</Button>
    </div>
    <span role="status" className="sr-only">{state === 'copied' ? t('ai_prompt.copied') : ''}</span>
    {state === 'failed' && data && <div className="space-y-1">
      <p id={alert} role="alert" className="text-xs text-danger">{t('ai_prompt.failed')}</p>
      <textarea aria-labelledby={alert} readOnly value={data.prompt} rows={8} onFocus={event => event.currentTarget.select()}
        className="w-full rounded-lg border border-app-line bg-inset p-3 font-mono text-xs leading-5 text-app-secondary" />
    </div>}
  </div>
}

// The finding's code as the prompt carries it: what the reader opened, a withheld line saying so.
function promptCode(data: components['schemas']['FindingCode'] | undefined, masked: string): string | null {
  if (data?.status !== 'shown' || !data.lines.length) return null
  return data.lines.map(line => line.masked === 'line' ? masked : line.text).join('\n')
}
