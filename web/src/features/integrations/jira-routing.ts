import type { JiraRouting } from '@/shared/api/queries'

export type JiraRule = JiraRouting['rules'][number]
export type JiraDestination = JiraRouting['destinations'][number]
export type JiraRef = { id?: string | null; key?: string | null; name?: string | null }

const STAR = Symbol('star')
const literal = (char: string) => `\\u{${char.codePointAt(0)!.toString(16)}}`

// One bracket expression's body (`!`, when present, still in front), as CPython's fnmatch.translate reads it: hyphens
// between two characters make ranges, a reversed range matches nothing and is dropped. Null: it matches nothing.
function bracket(body: string[]): string | null {
  const chunks: string[][] = []
  let start = 0
  let index = body[0] === '!' ? 2 : 1
  for (;;) {
    index = body.indexOf('-', index)
    if (index < 0) break
    chunks.push(body.slice(start, index))
    start = index + 1
    index += 3
  }
  const rest = body.slice(start)
  if (rest.length) chunks.push(rest)
  else chunks[chunks.length - 1].push('-')
  for (let at = chunks.length - 1; at > 0; at--) {
    if (chunks[at - 1][chunks[at - 1].length - 1].codePointAt(0)! > chunks[at][0].codePointAt(0)!) {
      chunks[at - 1] = [...chunks[at - 1].slice(0, -1), ...chunks[at].slice(1)]
      chunks.splice(at, 1)
    }
  }
  const chars = chunks.flat()
  if (!chars.length) return null
  if (chars.length === 1 && chars[0] === '!') return '.'
  const negated = chars[0] === '!'
  return `[${negated ? '^' : ''}${chunks.map((chunk, at) => (at === 0 && negated ? chunk.slice(1) : chunk).map(literal).join('')).join('-')}]`
}

// Python's fnmatchcase (what the server uses on lowercased names): *, ?, [seq] and [!seq], a port of CPython 3.12's
// fnmatch.translate. It reads code points, as Python does, and every character reaches the expression escaped. Each
// star before more pattern takes the shortest match and never gives it back (CPython's atomic group, here a lookahead
// and a backreference), so a pattern full of stars can't freeze the page.
export function globMatch(pattern: string, text: string): boolean {
  const chars = Array.from(pattern)
  const pieces: (string | typeof STAR)[] = []
  for (let index = 0; index < chars.length;) {
    const char = chars[index++]
    if (char === '*') { if (pieces[pieces.length - 1] !== STAR) pieces.push(STAR) }
    else if (char === '?') pieces.push('.')
    else if (char === '[') {
      let end = index
      if (chars[end] === '!') end++
      if (chars[end] === ']') end++
      while (end < chars.length && chars[end] !== ']') end++
      if (end >= chars.length) { pieces.push(literal('[')); continue }
      pieces.push(bracket(chars.slice(index, end)) ?? '(?!)')
      index = end + 1
    } else pieces.push(literal(char))
  }
  let source = ''
  let groups = 0
  for (let index = 0; index < pieces.length;) {
    if (pieces[index] !== STAR) { source += pieces[index++] as string; continue }
    let fixed = ''
    for (index++; index < pieces.length && pieces[index] !== STAR; index++) fixed += pieces[index] as string
    if (index === pieces.length) source += `.*${fixed}`
    else source += `(?=(.*?${fixed}))\\${++groups}`
  }
  return new RegExp(`^(?:${source})$`, 'su').test(text)
}

export function ruleMatches(rule: Pick<JiraRule, 'default' | 'assets' | 'patterns'>, key: string, name: string | null | undefined): boolean {
  if (rule.default) return true
  if (rule.assets.includes(key)) return true
  const lowered = (name ?? '').toLowerCase()
  return !!lowered && rule.patterns.some(pattern => globMatch(pattern.toLowerCase(), lowered))
}

// The rule that decides for an asset, as the server does: the first enabled one that matches and has a destination.
export function resolveRule(routing: Pick<JiraRouting, 'rules'>, key: string, name: string | null | undefined): JiraRule | null {
  return routing.rules.find(rule => rule.enabled && rule.destination && ruleMatches(rule, key, name)) ?? null
}

export const destinationOf = (routing: Pick<JiraRouting, 'destinations'>, id: string | null | undefined) =>
  routing.destinations.find(item => item.id === id) ?? null

// Project and issue type as Jira names them (shown raw): "SEC · Bug".
export function destinationTarget(destination: JiraDestination): string {
  const project = destination.project as JiraRef
  const issueType = destination.issue_type as JiraRef
  return [project.key ?? project.name, issueType.name].filter(Boolean).join(' · ')
}

// The API names a mapping field "mapping.<id>" (shape errors) or "<id>" (Jira's rules): both point at the same row.
const fieldOf = (field: string) => field.startsWith('mapping.') ? field.slice('mapping.'.length) : field
export const errorMap = (errors: { field: string; error: string }[] | undefined) =>
  Object.fromEntries((errors ?? []).map(item => [fieldOf(item.field), item.error]))
