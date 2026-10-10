import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FileUp, Plus, X } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { SPEC_MAX_BYTES, readSpec, toBase64, type Spec } from '@/features/analyses/wizard/model'

// The OpenAPI definition, optional: with it the scan calls the documented endpoints instead of crawling (the server's
// API mode). A file is read here to say what it holds; the server parses it again and only calls GET and HEAD.
export function ApiDocs({ host, isApi, value, invalid, onChange }: {
  host: string; isApi: boolean; value: Spec | null; invalid: boolean; onChange: (spec: Spec | null) => void
}) {
  const { t } = useTranslation('analyses')
  const [open, setOpen] = useState(isApi || !!value)
  const [error, setError] = useState('')
  const [reading, setReading] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const upload = useRef<HTMLButtonElement>(null)
  // Focus follows the person: onto the upload button when they open the block or remove the file.
  const focusUpload = useRef(false)
  useEffect(() => { if (focusUpload.current && upload.current) { focusUpload.current = false; upload.current.focus() } })

  const read = async (file: File) => {
    setError('')
    if (file.size > SPEC_MAX_BYTES) { setError(t('spec.too_large')); return }
    setReading(true)
    try {
      const bytes = new Uint8Array(await file.arrayBuffer())
      const parsed = readSpec(new TextDecoder().decode(bytes))
      if ('error' in parsed) { setError(parsed.error === 'invalid' ? t('spec.invalid') : t('spec.no_endpoints')); return }
      onChange({ mode: 'file', filename: file.name, content: toBase64(bytes), ...parsed })
    } finally { setReading(false) }
  }

  if (!open) return <Button variant="ghost" onClick={() => { focusUpload.current = true; setOpen(true) }} className="-ml-3 text-app-secondary"><Plus aria-hidden />{t('spec.add')}</Button>
  const url = value?.mode === 'url' ? value.url : ''
  return <section aria-labelledby="api-docs-title" className="space-y-4">
    <div className="space-y-1">
      <h3 id="api-docs-title" className="text-sm font-medium">{t('spec.title')} <span className="font-normal text-app-muted">{t('spec.optional')}</span></h3>
      <p className="text-sm text-app-muted">{isApi && !value ? t('spec.nudge') : t('spec.instead')}</p>
    </div>
    <div className="space-y-1.5">
      <input ref={input} id="spec-file" type="file" accept=".json,.yaml,.yml,application/json,application/yaml" className="sr-only" tabIndex={-1} aria-label={t('spec.choose')}
        onChange={event => { const file = event.target.files?.[0]; event.target.value = ''; if (file) void read(file) }} />
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <Button ref={upload} variant="outline" size="sm" disabled={reading} onClick={() => input.current?.click()}><FileUp aria-hidden />{value?.mode === 'file' ? t('spec.replace') : t('spec.choose')}</Button>
        <span role="status" className="flex min-w-0 items-center gap-1">{reading ? <span className="text-app-muted">{t('spec.reading')}</span>
          : value?.mode === 'file' ? <><span className="truncate font-mono text-app-secondary">{value.filename}</span>
              <span className="text-app-muted">· {t('spec.summary', { version: value.version, count: value.endpoints })}</span></> : null}</span>
        {value?.mode === 'file' && !reading && <Button variant="ghost" size="icon-sm" aria-label={t('spec.remove', { name: value.filename })} onClick={() => { focusUpload.current = true; onChange(null) }}><X /></Button>}
      </div>
      {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    </div>
    <div className="max-w-xl space-y-1.5">
      <label htmlFor="spec-url" className="text-sm text-app-secondary">{t('spec.url_label')}</label>
      {/* One source at a time: with a file loaded, the URL waits until it's removed. */}
      <Input id="spec-url" type="url" inputMode="url" value={url} placeholder={`https://${host}/openapi.json`} autoComplete="off" spellCheck={false} disabled={value?.mode === 'file'}
        onChange={event => { const next = event.target.value.trim(); setError(''); onChange(next ? { mode: 'url', url: next } : null) }}
        aria-invalid={invalid || undefined} aria-describedby="spec-url-note" className="border-app-line bg-app-soft font-mono" />
      <p id="spec-url-note" role="status" className={`text-xs ${invalid ? 'text-danger' : 'text-app-muted'}`}>{invalid ? t('spec.url_foreign', { host }) : value?.mode === 'file' ? t('spec.url_file_loaded') : ''}</p>
    </div>
  </section>
}

