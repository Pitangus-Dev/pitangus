import { useCallback } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { imageRepositoriesQuery } from '@/shared/api/queries'

// The picker's search for the repository an image is built from: analyzed repositories first, then the ones the
// GitHub App or a connected token reach, which can be linked before their first scan.
export function useRepositorySearch() {
  const { t } = useTranslation('compliance')
  const queryClient = useQueryClient()
  return useCallback((q: string) => queryClient.fetchQuery(imageRepositoriesQuery(q)).then(page => ({
    options: page.items.map(item => ({ id: item.key, label: item.name, hint: item.analyzed ? undefined : t('evidence.origin.not_analyzed') })),
    total: page.total })), [queryClient, t])
}
