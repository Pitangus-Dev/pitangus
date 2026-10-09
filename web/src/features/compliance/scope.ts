// The scope of the portfolio evidence files, and how it travels to the API (POST body and GET query string).
export type Scope = { kind: 'all' | 'account' | 'assets'; account: string; assets: { key: string; name: string; image: boolean }[]; images: boolean }
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
export const scopeReady = (scope: Scope) => scope.kind === 'all' || (scope.kind === 'account' ? Boolean(scope.account) : scope.assets.length > 0)
