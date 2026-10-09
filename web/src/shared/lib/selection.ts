// Findings chosen across several assets, one part per asset (in the order they first appear): how triage and Jira take
// such a selection. Items without an asset are left out.
export function byAsset(items: { fingerprint: string; asset?: string | null }[]): { asset: string; fingerprints: string[] }[] {
  const groups = new Map<string, string[]>()
  for (const item of items) if (item.asset) groups.set(item.asset, [...(groups.get(item.asset) ?? []), item.fingerprint])
  return [...groups.entries()].map(([asset, fingerprints]) => ({ asset, fingerprints }))
}
