import { useEffect, useId, useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Trans, useTranslation } from 'react-i18next'
import { ArrowRight, LoaderCircle, ShieldCheck, Sparkles } from 'lucide-react'
import { apiPost } from '@/shared/api/client'
import { Button } from '@/shared/ui/button'
import { Input } from '@/shared/ui/input'
import { BRAND } from '@/shared/lib/brand'

const NAME_MAX = 34

// GitHub's manifest flow: the form goes to github.com with the manifest, the administrator confirms there and GitHub
// sends the browser back to the server, which keeps the App's key. Nothing secret passes through the panel.
function postToGitHub(url: string, manifest: string) {
  const form = document.createElement('form')
  form.method = 'post'
  form.action = url
  const field = document.createElement('input')
  field.type = 'hidden'
  field.name = 'manifest'
  field.value = manifest
  form.append(field)
  document.body.append(form)
  form.submit()
}

export function GitHubAppCreate({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation('sources')
  const id = useId()
  const [organization, setOrganization] = useState('')
  const [edited, setEdited] = useState<string | null>(null)
  const [anyAccount, setAnyAccount] = useState(false)
  const [error, setError] = useState('')
  const owner = organization.trim()
  // The suggestion follows the organization until the administrator writes a name of their own.
  const name = edited ?? (owner ? t('github.create.name_for', { brand: BRAND.name, organization: owner }) : t('github.steps.name.app_name_example', { brand: BRAND.name })).slice(0, NAME_MAX)
  const mutation = useMutation({
    mutationFn: () => apiPost('/api/integrations/github/manifest', 'create-github-app', { name: name.trim(), organization: owner || null, any_account: anyAccount }),
    onSuccess: result => postToGitHub(result.url, result.manifest),
    onError: caught => setError(caught instanceof Error ? caught.message : String(caught)),
  })
  // After a successful start the page navigates away to GitHub: busy until it does. Coming back with the browser's
  // Back button can restore this page from the back-forward cache, so it is unlocked then.
  const { reset } = mutation
  useEffect(() => {
    const restored = (event: PageTransitionEvent) => { if (event.persisted) reset() }
    window.addEventListener('pageshow', restored)
    return () => window.removeEventListener('pageshow', restored)
  }, [reset])
  const busy = mutation.isPending || mutation.isSuccess
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (busy || !name.trim()) return
    setError('')
    mutation.mutate()
  }

  return <form onSubmit={submit} aria-busy={busy || undefined} className="space-y-4 rounded-xl border border-brand/30 bg-panel p-4">
    <div className="flex items-start gap-3">
      <Sparkles className="mt-0.5 size-4 shrink-0 text-brand" />
      <div><h3 className="text-sm font-medium">{t('github.create.title')}</h3><p className="mt-1 text-xs leading-5 text-app-muted">{t('github.create.description')}</p></div>
    </div>
    {!canManage && <p className="rounded-lg border border-app-line bg-app-soft px-3 py-2 text-xs text-app-muted">{t('github.form.admin_only')}</p>}
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1.5"><label htmlFor={`${id}-org`} className="text-xs text-app-muted">{t('github.create.organization')}</label>
        <Input id={`${id}-org`} value={organization} disabled={!canManage || busy} maxLength={39} aria-describedby={`${id}-org-help`}
          onChange={event => setOrganization(event.target.value.replace(/[^A-Za-z0-9-]/g, ''))} className="border-app-line bg-app-soft" />
        <p id={`${id}-org-help`} className="text-[11px] leading-4 text-app-subtle">{t('github.create.organization_help')}</p></div>
      <div className="space-y-1.5"><label htmlFor={`${id}-name`} className="text-xs text-app-muted">{t('github.create.name')}</label>
        <Input id={`${id}-name`} value={name} required disabled={!canManage || busy} maxLength={NAME_MAX} aria-describedby={`${id}-name-help`}
          onChange={event => setEdited(event.target.value)} className="border-app-line bg-app-soft" />
        <p id={`${id}-name-help`} className="text-[11px] leading-4 text-app-subtle">{t('github.create.name_help')}</p></div>
    </div>
    <label className="flex cursor-pointer items-start gap-2 text-xs leading-5 text-app-muted has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-60">
      <input type="checkbox" checked={anyAccount} disabled={!canManage || busy} onChange={event => setAnyAccount(event.target.checked)} className="mt-0.5 size-4 accent-brand" />
      <span><Trans t={t} i18nKey="github.create.any_account" components={{ b: <strong className="font-medium text-app-secondary" /> }} /></span>
    </label>
    {error && <div role="alert" className="rounded-lg border border-danger-line bg-danger-soft px-3 py-2 text-xs text-danger">{error}</div>}
    <div className="flex flex-wrap items-center gap-3">
      <Button type="submit" disabled={!canManage} aria-disabled={busy || undefined} className="bg-primary text-primary-foreground hover:bg-primary/90">
        {busy ? <LoaderCircle className="motion-safe:animate-spin" /> : <ArrowRight />}{busy ? t('github.create.opening') : t('github.create.submit')}</Button>
      <p className="flex items-start gap-2 text-[11px] leading-4 text-app-subtle"><ShieldCheck className="mt-0.5 size-3 shrink-0" />{t('github.create.note')}</p>
    </div>
  </form>
}
