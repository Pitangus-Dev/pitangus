// What the evidence files cover: one asset (its own exports), one organization, several chosen assets or everything; and
// how a scope of more than one travels to the API (POST body and GET query string).
export type Scope = { kind: 'one' | 'account' | 'assets' | 'all'; account: string; assets: { key: string; name: string; image: boolean }[]; images: boolean }
export const ALL: Scope = { kind: 'all', account: '', assets: [], images: true }

// What the portfolio files are about, in the shape the API takes: the POST body and the GET query string.
export function scopeBody(scope: Scope): { assets?: string[]; account?: string; include_images?: boolean } {
  if (scope.kind === 'account') return { account: scope.account, include_images: scope.images }
  if (scope.kind === 'assets') return { assets: scope.assets.map(item => item.key), include_images: scope.images }
  return {}
}
export function scopeQuery(scope: Scope): string {
  const body = scopeBody(scope)
  return [...(body.assets ?? []).map(key => `assets=${encodeURIComponent(key)}`), ...(body.account ? [`account=${encodeURIComponent(body.account)}`] : []),
    ...(body.include_images === false ? ['include_images=false'] : [])].join('&')
}
// A single asset is ready once picked, which the hub knows (it holds the asset); here only the portfolio kinds.
export const scopeReady = (scope: Scope) => scope.kind === 'all' || (scope.kind === 'account' ? Boolean(scope.account) : scope.kind === 'assets' && scope.assets.length > 0)
