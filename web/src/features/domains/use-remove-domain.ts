import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { apiPost } from '@/shared/api/client'
import { keys } from '@/shared/api/queries'
import { useConfirm } from '@/shared/ui/confirm'
import type { Domain } from '@/features/domains/domains'

// Asks before removing a domain, saying what goes with it; the caller decides where focus goes afterwards.
export function useRemoveDomain(onRemoved: (domain: Domain) => void) {
  const { t } = useTranslation('sources')
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const removal = useMutation({
    mutationFn: (domain: Domain) => apiPost('/api/domains/remove', 'remove-domain', { domain_id: domain.id }),
    onSuccess: (_, domain) => {
      void queryClient.invalidateQueries({ queryKey: keys.domains })
      void queryClient.invalidateQueries({ queryKey: keys.assets })
      onRemoved(domain)
    },
  })
  const ask = (domain: Domain) => void confirm({
    title: t('domains.list.remove_title', { host: domain.host }),
    description: domain.runs ? t('domains.list.confirm_remove_runs', { count: domain.runs }) : t('domains.list.confirm_remove'),
    confirmLabel: t('domains.list.remove'), destructive: true,
  }).then(ok => { if (ok) removal.mutate(domain) })
  return { ask, removal }
}
