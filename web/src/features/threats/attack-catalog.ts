import type { Component } from '@/features/threats/threat-model-types'

// All of MITRE ATT&CK Enterprise as the server bundles it: [English name, tactic IDs, MITRE platforms] per live
// technique, with our translations apart and the one table that turns a component into its suggestions
// (pitangus/modules/threats/methods.py, SUGGESTION_RULES; the panel only applies it).
export type AttackCatalog = {
  version: string; source: string
  counts: { total: number; techniques: number; subtechniques: number; revoked: number; deprecated: number }
  tactics: Record<string, string>; platforms: string[]
  techniques: Record<string, [string, string[], string[]]>; revoked: Record<string, string | null>; deprecated: Record<string, string>
  translations: Record<string, { tactics: Record<string, string>; techniques: Record<string, string> }>
  suggestions: { kinds: Partial<Record<string, { platforms: string[]; tactics: string[] }>>; hosts: string[]; internet_tactic: string
    container_platform: string; container_terms: string[] }
}

export type Basis = { platforms: string[]; tactics: string[] }
export type SuggestionGroup = { id: string; tactic: string; components: Component[] }

const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Same rule as suggestion_basis() on the server: null for an actor or a type of the team's own.
export function basisOf(attack: AttackCatalog, component: Component): Basis | null {
  const rule = attack.suggestions.kinds[component.kind]
  if (!rule) return null
  const { hosts, container_platform, container_terms, internet_tactic } = attack.suggestions
  const containers = new RegExp(`\\b(?:${container_terms.map(escape).join('|')})\\b`, 'i')
  const platforms = [...rule.platforms, ...(rule.platforms.some(name => hosts.includes(name)) && containers.test(component.technology ?? '') ? [container_platform] : [])]
  const order = Object.keys(attack.tactics)
  const tactics = [...new Set([...rule.tactics, ...(component.internet_facing ? [internet_tactic] : [])])].sort((a, b) => order.indexOf(a) - order.indexOf(b))
  return { platforms, tactics }
}

// Techniques (not sub-techniques) MITRE lists for one of the platforms in one of the tactics.
export function suggestedFor(attack: AttackCatalog, component: Component): string[] {
  const basis = basisOf(attack, component)
  if (!basis) return []
  return Object.entries(attack.techniques).filter(([id, [, tactics, platforms]]) => !id.includes('.')
    && platforms.some(name => basis.platforms.includes(name)) && tactics.some(key => basis.tactics.includes(key))).map(([id]) => id)
}

// One row per technique with the components it applies to (and isn't mapped to yet), in kill-chain order: each under
// the first of its tactics that one of those components asked for.
export function groupSuggestions(attack: AttackCatalog, components: Component[], mapped: (id: string, element: string) => boolean): SuggestionGroup[] {
  const order = Object.keys(attack.tactics)
  const rank = (key: string) => order.indexOf(key)
  const groups = new Map<string, SuggestionGroup>()
  for (const component of components) {
    const wanted = basisOf(attack, component)?.tactics ?? []
    for (const id of suggestedFor(attack, component)) {
      if (mapped(id, component.id)) continue
      const tactic = attack.techniques[id][1].find(key => wanted.includes(key)) ?? attack.techniques[id][1][0]
      const group = groups.get(id)
      if (!group) groups.set(id, { id, tactic, components: [component] })
      else { group.components.push(component); if (rank(tactic) < rank(group.tactic)) group.tactic = tactic }
    }
  }
  return [...groups.values()].sort((a, b) => rank(a.tactic) - rank(b.tactic) || a.id.localeCompare(b.id))
}

// Our name for a technique in the reader's language, when it says something MITRE's doesn't ("Phishing" stays once).
export function translationOf(attack: AttackCatalog, locale: string, id: string): string | undefined {
  const translated = attack.translations[locale]?.techniques[id]
  return translated && translated !== attack.techniques[id]?.[0] ? translated : undefined
}
export const tacticTranslation = (attack: AttackCatalog, locale: string, id: string) => attack.translations[locale]?.tactics[id]

// Search by ID, MITRE's name, our translation or a tactic (in either language).
export function matches(attack: AttackCatalog, locale: string, id: string, needle: string): boolean {
  if (!needle) return true
  const [name, tactics] = attack.techniques[id]
  const words = [id, name, translationOf(attack, locale, id) ?? '', ...tactics.flatMap(key => [attack.tactics[key] ?? key, tacticTranslation(attack, locale, key) ?? ''])]
  return words.some(word => word.toLowerCase().includes(needle))
}
