// What kind of asset a key names: the server's own rule (`domain:…`, `image:…`, anything else is code).
export type AssetKind = 'repository' | 'image' | 'domain'

export const assetKindOf = (key: string | null | undefined): AssetKind =>
  key?.startsWith('domain:') ? 'domain' : key?.startsWith('image:') ? 'image' : 'repository'
