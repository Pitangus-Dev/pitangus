import { useId } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { ArrowSquareOutIcon } from '@phosphor-icons/react'
import { Bone } from '@/shared/ui/loading'
import { Button } from '@/shared/ui/button'
import { Notice } from '@/shared/ui/notice'
import { findingCodeQuery } from '@/shared/api/queries'
import type { components } from '@/shared/api/schema'

type Line = components['schemas']['FindingCode']['lines'][number]

const REASON = {
  secret: 'code.reason.secret', imported: 'code.reason.imported', symlink: 'code.reason.symlink',
  secret_other_commit: 'code.reason.secret_other_commit', local: 'code.reason.local', no_commit: 'code.reason.no_commit', no_location: 'code.reason.no_location',
  file_gone: 'code.reason.file_gone', file_changed: 'code.reason.file_changed', binary: 'code.reason.binary',
  repository_gone: 'code.reason.repository_gone', repository_unreachable: 'code.reason.repository_unreachable',
} as const

// A finding's code is never stored: it is read from the repository, at the commit its scan read, when the detail
// opens, with every secret in the file masked by the server. Only the reader's browser holds it, while it is open.
export function FindingCode({ runId, fingerprint }: { runId: string; fingerprint: string }) {
  const { t } = useTranslation('findings')
  const heading = useId()
  const { data, isPending, isError, refetch, isFetching } = useQuery(findingCodeQuery(runId, fingerprint))
  // Nothing to read for what has no place in a file (or an answer that isn't one).
  if (data === null || data?.reason === 'not_code') return null
  // The heading names the finding's own lines; the block around them is context.
  const own = data?.lines.filter(line => line.focus) ?? []
  const first = own[0]?.number
  const last = own.at(-1)?.number
  return <section aria-labelledby={heading} className="mt-4">
    <h3 id={heading} className="mb-1 text-xs font-medium text-app-muted">{t('code.title')}{data?.status === 'shown' && first && last
      ? <span className="font-normal text-app-subtle"> · {first === last ? t('code.line', { line: first }) : t('code.lines', { first, last })}</span> : null}</h3>
    {isPending ? <div role="status" aria-busy="true"><span className="sr-only">{t('code.loading')}</span>
      <div aria-hidden className="space-y-2 rounded-lg border border-app-line bg-inset p-3">{['w-2/3', 'w-1/2', 'w-3/4', 'w-1/3'].map(width => <Bone key={width} className={`h-3 ${width}`} />)}</div>
    </div>
      : isError ? <Notice tone="critical" role="alert"><p>{t('code.error')}</p>
        <Button size="xs" variant="outline" className="mt-2" disabled={isFetching} onClick={() => void refetch()}>{t('code.retry')}</Button></Notice>
      : data.status === 'shown' ? <Lines lines={data.lines} labelledBy={heading} />
      : <p className="text-sm text-app-secondary">{t(REASON[data.reason as keyof typeof REASON] ?? 'code.reason.unknown')}
        {data.reason === 'repository_unreachable' && <Button size="xs" variant="outline" className="ml-2" disabled={isFetching} onClick={() => void refetch()}>{t('code.retry')}</Button>}</p>}
    {data && (data.status === 'shown' || data.permalink) && <p className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-app-subtle">
      {data.status === 'shown' && <span>{t(data.lines.some(line => line.masked) ? 'code.read_now_masked' : 'code.read_now')}</span>}
      {data.permalink && <a href={data.permalink} target="_blank" rel="noreferrer" className="inline-flex min-h-6 items-center gap-1 text-brand underline underline-offset-2">
        {t('code.open_github')}<ArrowSquareOutIcon className="size-3" /><span className="sr-only">{t('web.new_tab')}</span></a>}
    </p>}
  </section>
}

function Lines({ lines, labelledBy }: { lines: Line[]; labelledBy: string }) {
  const { t } = useTranslation('findings')
  const width = String(lines.at(-1)?.number ?? 0).length
  // Focusable so a keyboard can scroll a long line into view.
  return <pre tabIndex={0} aria-labelledby={labelledBy} className="overflow-x-auto rounded-lg border border-app-line bg-inset py-2 font-mono text-xs leading-5" translate="no">
    <code className="grid min-w-max">{lines.map(line => <span key={line.number} className={`flex gap-4 px-3 ${line.focus ? 'bg-panel text-app-fg' : 'text-app-muted'}`}>
      <span aria-hidden className={`shrink-0 text-right tabular-nums select-none ${line.focus ? 'font-medium text-app-fg' : 'text-app-subtle'}`} style={{ width: `${width}ch` }}>{line.number}</span>
      {line.focus && <span className="sr-only">{t('code.finding_line')}</span>}
      {line.masked === 'line'
        ? <span className="font-sans text-app-subtle italic">{t('code.masked_line')}</span>
        : <span className="whitespace-pre">{line.text || ' '}</span>}
    </span>)}</code>
  </pre>
}
