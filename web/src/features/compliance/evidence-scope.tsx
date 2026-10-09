import { useCallback, useId, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { Select, SelectContent, SelectItem, SelectTrigger } from '@/shared/ui/select'
import { evidenceAssetsQuery } from '@/shared/api/queries'
import type { Scope } from '@/features/compliance/scope'

// The scope picker: one asset (its picker comes in `one`, the hub holds it), one organization's repositories, chosen
// repositories and images, or everything; with a repository come the images built from it unless that is turned off.
export function EvidenceScope({ scope, accounts, total, one, onChange }: { scope: Scope; accounts: string[]; total: number; one: ReactNode; onChange: (scope: Scope) => void }) {
  const { t } = useTranslation('compliance')
  const queryClient = useQueryClient()
  const name = useId()
  const search = useCallback((q: string) => queryClient.fetchQuery(evidenceAssetsQuery(q)).then(page => ({
    options: page.items.filter(asset => !scope.assets.some(item => item.key === asset.key))
      .map(asset => ({ id: asset.key, label: asset.name, hint: asset.kind === 'image' ? t('evidence.image') : t('evidence.repository'), image: asset.kind === 'image' })),
    total: page.total })), [queryClient, scope.assets, t])
  const kinds: [Scope['kind'], string][] = [['one', t('evidence.scope.one')], ['account', t('evidence.scope.account')], ['assets', t('evidence.scope.assets')],
    ['all', t('evidence.scope.all', { count: total })]]
  return <fieldset className="min-w-0 space-y-3">
    <legend className="mb-3 text-xs text-app-muted"><span aria-hidden>1 · </span>{t('evidence.scope.legend')}</legend>
    <div className="grid w-full grid-cols-2 gap-1 rounded-xl sm:flex sm:w-fit sm:max-w-full sm:flex-wrap border border-app-line bg-inset p-1">{kinds.map(([kind, label]) =>
      <label key={kind} className={`flex min-h-9 cursor-pointer items-center gap-2 rounded-lg border px-3 text-sm whitespace-nowrap has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand ${scope.kind === kind ? 'border-brand bg-brand/10 text-brand' : 'border-transparent text-app-muted hover:text-app-fg'}`}>
        <input type="radio" name={name} value={kind} checked={scope.kind === kind} onChange={() => onChange({ ...scope, kind })} className="sr-only" />{label}</label>)}</div>
    {scope.kind === 'one' && one}
    {scope.kind === 'account' && (accounts.length
      ? <div className="max-w-sm"><Select value={scope.account || null} onValueChange={value => { if (value) onChange({ ...scope, account: String(value) }) }}>
          <SelectTrigger aria-label={t('evidence.scope.account')} className="w-full border-app-line bg-inset"><span className="min-w-0 truncate">{scope.account || t('evidence.scope.choose_account')}</span></SelectTrigger>
          <SelectContent className="border border-app-line bg-panel p-1 text-app-fg shadow-xl">{accounts.map(account => <SelectItem key={account} value={account}>{account}</SelectItem>)}</SelectContent>
        </Select></div>
      : <p className="text-xs text-app-muted">{t('evidence.scope.no_accounts')}</p>)}
    {scope.kind === 'assets' && <div className="space-y-2">
      <Combobox className="max-w-sm" label={t('evidence.scope.add_label')} placeholder={t('evidence.scope.add')} emptyText={t('evidence.no_match')} value={null} search={search}
        onSelect={option => onChange({ ...scope, assets: [...scope.assets, { key: option.id, name: option.label, image: Boolean((option as ComboOption & { image?: boolean }).image) }] })} />
      {scope.assets.length > 0 && <ul aria-label={t('evidence.scope.chosen')} className="flex flex-wrap gap-2">{scope.assets.map(item => <li key={item.key}
        className="flex max-w-full items-center gap-1 rounded-lg border border-app-line bg-inset py-0.5 pr-1 pl-2 text-xs">
        <span className="min-w-0 truncate">{item.name}</span><span className="shrink-0 text-app-subtle">· {item.image ? t('evidence.image') : t('evidence.repository')}</span>
        <button type="button" aria-label={t('evidence.scope.remove', { name: item.name })} onClick={() => onChange({ ...scope, assets: scope.assets.filter(other => other.key !== item.key) })}
          className="grid size-6 shrink-0 place-items-center rounded-md text-app-muted hover:bg-app-soft hover:text-app-fg"><X className="size-3.5" /></button></li>)}</ul>}
    </div>}
    {(scope.kind === 'account' || scope.kind === 'assets') && <label className="flex min-h-6 items-center gap-2 text-sm">
      <input type="checkbox" checked={scope.images} onChange={event => onChange({ ...scope, images: event.target.checked })} className="size-4 accent-brand" />
      {t('evidence.scope.images')}</label>}
  </fieldset>
}
