import { useQuery } from '@tanstack/react-query'
import { useCallback } from 'react'
import { api } from '@/shared/api/http'

export type BatchSummary = { id: string; label: string; status: 'running' | 'done' | 'cancelled'; created_at: string; by: string; total: number
  pending: number; running: number; done: number; failed: number; critical: number; high: number; eta_seconds: number
  failed_items: { name: string; error: string }[] }

// The active batch, polled every 5 s only while one runs, and a way to refresh it after starting one.
export function useBatches() {
  const result = useQuery({
    queryKey: ['batches'],
    queryFn: ({ signal }) => api.get<{ active: BatchSummary | null; recent: BatchSummary[] }>('/api/repositories/batches', { signal }),
    refetchInterval: query => query.state.data?.active ? 5000 : false,
  })
  const state = result.data ?? null
  const reload = useCallback(() => result.refetch(), [result])
  return { active: state?.active ?? null, last: state?.recent[0] ?? null, reload }
}
