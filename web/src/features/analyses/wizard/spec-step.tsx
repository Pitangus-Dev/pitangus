import { useRef, useState, type DragEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { FileCheck2, FileUp } from 'lucide-react'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/shared/ui/tabs'
import { StepFrame } from '@/features/analyses/wizard/step-frame'
import { SPEC_MAX_BYTES, inScope, readSpec, toBase64, type Spec } from '@/features/analyses/wizard/model'

// The API's OpenAPI definition: required, since without it there is nothing to call (crawling is the web scan's job).
// A file is read here to say what it holds; the server parses it again and only calls its GET and HEAD operations.
export function SpecStep({ host, scopeHosts, value, onChange, onBack, onContinue }: {
  host: string; scopeHosts: string[]; value: Spec | null; onChange: (spec: Spec | null) => void; onBack: () => void; onContinue: () => void
}) {
  const { t } = useTranslation('analyses')
  const [tab, setTab] = useState<'file' | 'url'>(value?.mode ?? 'file')
  const [error, setError] = useState('')
  const [reading, setReading] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [url, setUrl] = useState(value?.mode === 'url' ? value.url : '')
  const input = useRef<HTMLInputElement>(null)
  const urlError = url.trim() && !inScope(url.trim(), host, scopeHosts) ? t('spec.url_foreign', { host }) : ''

  const read = async (file: File) => {
    setError('')
    if (file.size > SPEC_MAX_BYTES) { onChange(null); setError(t('spec.too_large')); return }
    setReading(true)
    try {
      const bytes = new Uint8Array(await file.arrayBuffer())
      const parsed = readSpec(new TextDecoder().decode(bytes))
      if ('error' in parsed) { onChange(null); setError(parsed.error === 'invalid' ? t('spec.invalid') : t('spec.no_endpoints')); return }
      onChange({ mode: 'file', filename: file.name, content: toBase64(bytes), ...parsed })
    } finally { setReading(false) }
  }
  const drop = (event: DragEvent) => { event.preventDefault(); setDragging(false); const file = event.dataTransfer.files[0]; if (file) void read(file) }
  const setUrlValue = (next: string) => { setUrl(next); const clean = next.trim(); onChange(clean && inScope(clean, host, scopeHosts) ? { mode: 'url', url: clean } : null) }
  const ready = value?.mode === tab

  return <StepFrame title={t('spec.title')} onBack={onBack} onContinue={onContinue} continueDisabled={!ready}>
    <Tabs value={tab} onValueChange={next => { setTab(next as 'file' | 'url'); setError('') }}>
      <TabsList aria-label={t('spec.title')}>
        <TabsTrigger value="file" className="px-3">{t('spec.tab_file')}</TabsTrigger>
        <TabsTrigger value="url" className="px-3">{t('spec.tab_url')}</TabsTrigger>
      </TabsList>
      <TabsContent value="file" className="space-y-3 pt-3">
        <div onDragOver={event => { event.preventDefault(); setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={drop}
          className={`flex flex-col items-center gap-3 rounded-xl border border-dashed p-8 text-center motion-safe:transition ${dragging ? 'border-brand bg-brand/10' : 'border-app-line bg-inset'}`}>
          <FileUp className="size-6 text-app-muted" aria-hidden />
          <p className="text-sm text-app-muted">{t('spec.drop')}</p>
          <input ref={input} id="spec-file" type="file" accept=".json,.yaml,.yml,application/json,application/yaml" className="sr-only" tabIndex={-1}
            onChange={event => { const file = event.target.files?.[0]; event.target.value = ''; if (file) void read(file) }} />
          <Button variant="outline" disabled={reading} onClick={() => input.current?.click()}>{value?.mode === 'file' ? t('spec.replace') : t('spec.choose')}</Button>
        </div>
        <div role="status" className="text-sm">
          {reading ? <span className="text-app-muted">{t('spec.reading')}</span>
            : value?.mode === 'file' && !error ? <span className="flex items-center gap-2 text-success"><FileCheck2 className="size-4" aria-hidden /><span className="font-mono text-app-secondary">{value.filename}</span> · {t('spec.summary', { version: value.version, count: value.endpoints })}</span> : null}
        </div>
        {error && <p role="alert" className="text-sm text-danger">{error}</p>}
      </TabsContent>
      <TabsContent value="url" className="space-y-1.5 pt-3">
        <label htmlFor="spec-url" className="text-sm text-app-secondary">{t('spec.url_label')}</label>
        <Input id="spec-url" type="url" inputMode="url" value={url} onChange={event => setUrlValue(event.target.value)} placeholder={`https://${host}/openapi.json`} autoComplete="off" spellCheck={false}
          aria-invalid={!!urlError || undefined} aria-describedby="spec-url-error" className="border-app-line bg-app-soft font-mono" />
        <p id="spec-url-error" role="status" className="text-xs text-danger">{urlError}</p>
      </TabsContent>
    </Tabs>
  </StepFrame>
}
