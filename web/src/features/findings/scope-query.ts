import { useQuery } from '@tanstack/react-query'
import { findingsScopeQuery } from '@/shared/api/queries'
import { scopeQuery, scopeReady, type Scope } from '@/shared/lib/scope'
import type { FindingTab } from '@/features/findings/finding-model'

// The findings of a scope of several assets, by tab. The page reads it too: the names of the chosen assets come with it.
export function useScopeFindings(scope: Scope, tab: FindingTab) {
  return useQuery({ ...findingsScopeQuery(scopeQuery(scope), tab), enabled: scope.kind !== 'one' && scopeReady(scope) })
}
