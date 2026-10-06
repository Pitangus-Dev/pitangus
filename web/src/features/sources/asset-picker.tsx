import { useCallback, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Combobox, type ComboOption } from '@/shared/ui/combobox'
import { api, query } from '@/shared/api/http'
import type { Page } from '@/shared/lib/types'
import { assetOption, type Asset } from '@/features/sources/asset-option'

// Selector de repositorio con búsqueda en el servidor; arranca con el de actividad más reciente o el pedido.
// `onLoaded` tells an empty workspace (0) from a failed first load ('error').
export function AssetPicker({ value, onChange, initialKey, label, placeholder, onLoaded }: { value: Asset | null; onChange: (asset: Asset | null) => void; initialKey?: string | null
  label?: string; placeholder?: string; onLoaded?: (total: number | 'error') => void }) {
  const { t } = useTranslation('sources')
  const started = useRef(false)
  const search = useCallback(async (text: string) => {
    const page = await api.get<Page<Asset>>(`/api/assets?${query({ q: text || undefined, limit: 50 })}`)
    return { options: page.items.map(assetOption), total: page.total, items: page.items }
  }, [])
  useEffect(() => {
    if (value || started.current) return
    started.current = true
    api.get<Page<Asset>>(`/api/assets?${query({ key: initialKey || undefined, limit: 1 })}`)
      .then(page => { onChange(page.items[0] ?? null); onLoaded?.(page.total) }).catch(() => { onChange(null); onLoaded?.('error') })
  }, [value, initialKey, onChange, onLoaded])
  const pick = (option: ComboOption) => { void search(option.label).then(result => onChange(result.items.find(item => item.key === option.id) ?? null)) }
  return <Combobox label={label ?? t('asset.label')} placeholder={placeholder ?? t('asset.placeholder')} value={value ? assetOption(value) : null} search={search} onSelect={pick} />
}
