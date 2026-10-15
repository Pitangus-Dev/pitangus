// How a custom property's value reads as text: the same rules as the reports (threats/report.py).

export const isPlain = (value: unknown): value is string | number | boolean => ['string', 'number', 'boolean'].includes(typeof value)
// A section title from its key: «data_retention» reads «Data retention».
export const headingOf = (key: string) => { const words = key.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim(); return words.charAt(0).toUpperCase() + words.slice(1) }
export const valueText = (value: unknown): string => isPlain(value) ? String(value)
  : Array.isArray(value) && value.every(isPlain) ? value.map(String).join(', ') : JSON.stringify(value)
