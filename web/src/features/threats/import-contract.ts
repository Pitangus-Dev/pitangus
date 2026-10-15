// The import contract, from the same JSON Schema the server generates (make openapi): the AI prompt's lists of
// values and the downloadable schema can't drift from what the importer accepts.
import schema from '@/examples/threat-models/schema.json'
import minimalEn from '@/examples/threat-models/minimal.en.json'
import minimalEs from '@/examples/threat-models/minimal.es.json'
import type { Locale } from '@/shared/i18n'

export const IMPORT_SCHEMA = schema

type Property = { enum?: unknown[]; examples?: unknown[]; pattern?: string; items?: Property; 'x-pitangus-attack-version'?: string }
const defs = schema.$defs as unknown as Record<string, { properties: Record<string, Property>; 'x-pitangus-aliases'?: Record<string, string> }>
const list = (values: unknown[] | undefined) => (values ?? []).filter(value => value !== null).join(', ')
const property = (def: string, name: string) => defs[def].properties[name]

export function promptValues(locale: Locale, example: string) {
  const minimal = locale === 'es' ? minimalEs : minimalEn
  return {
    protocols: list(property('flow', 'protocol').examples),
    kinds: list(property('component', 'kind').examples),
    bases: list(property('component', 'custom_base').enum),
    classifications: list(property('component', 'data').items?.examples),
    methodologies: list(property('model', 'methodology').enum),
    modules: list(property('model', 'custom_modules').items?.enum),
    severities: list(property('manual_threat', 'severity').enum),
    levels: list(property('manual_threat', 'likelihood').enum),
    statuses: list(property('attack_mapping', 'status').enum),
    stages: Object.keys((property('model', 'pasta') as unknown as { properties: Record<string, unknown> }).properties).join(', '),
    technique_pattern: property('attack_mapping', 'technique').pattern ?? '',
    attack_version: property('attack_mapping', 'technique')['x-pitangus-attack-version'] ?? '',
    // The field synonyms the importer reads as ours, per object: «manual_threat: component_id → element, …».
    aliases: Object.entries(defs).map(([name, def]) => [name, Object.entries(def['x-pitangus-aliases'] ?? {})] as const).filter(([, pairs]) => pairs.length)
      .map(([name, pairs]) => `${name} (${pairs.map(([alias, field]) => `${alias} → ${field}`).join(', ')})`).join('; '),
    minimal: JSON.stringify(minimal, null, 2),
    example,
  }
}
