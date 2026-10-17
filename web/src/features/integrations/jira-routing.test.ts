import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { globMatch } from '@/features/integrations/jira-routing'

// The server routes with Python's fnmatchcase; the panel previews the same decision with globMatch. This reference
// reads a pattern the way fnmatch's documentation describes it, character by character (code points) and with no
// regular expression, so the two implementations only agree when globMatch's translation is right.
function reference(pattern: string, text: string): boolean {
  const chars = Array.from(pattern)
  const tokens: ('*' | ((char: string) => boolean))[] = []
  for (let index = 0; index < chars.length;) {
    const char = chars[index++]
    if (char === '*') { tokens.push('*'); continue }
    if (char === '?') { tokens.push(() => true); continue }
    if (char === '[') {
      let end = index
      if (chars[end] === '!') end++
      if (chars[end] === ']') end++
      while (end < chars.length && chars[end] !== ']') end++
      if (end < chars.length) {
        tokens.push(set(chars.slice(index, end)))
        index = end + 1
        continue
      }
    }
    tokens.push(other => other === char)
  }
  const target = Array.from(text)
  const memo = new Map<number, boolean>()
  const match = (at: number, from: number): boolean => {
    const key = at * (target.length + 1) + from
    if (memo.has(key)) return memo.get(key)!
    const token = tokens[at]
    const result = token === undefined ? from === target.length
      : token === '*' ? match(at + 1, from) || (from < target.length && match(at, from + 1))
        : from < target.length && token(target[from]) && match(at + 1, from + 1)
    memo.set(key, result)
    return result
  }
  return match(0, 0)
}

// `[...]`: a leading `!` negates; `x-y` is a range (a reversed one matches nothing); anything else stands for itself.
function set(body: string[]): (char: string) => boolean {
  const negated = body[0] === '!'
  const items = negated ? body.slice(1) : body
  const ranges: [number, number][] = []
  for (let index = 0; index < items.length;) {
    if (index + 2 < items.length && items[index + 1] === '-') {
      ranges.push([items[index].codePointAt(0)!, items[index + 2].codePointAt(0)!])
      index += 3
    } else {
      const point = items[index].codePointAt(0)!
      ranges.push([point, point])
      index++
    }
  }
  return char => ranges.some(([low, high]) => low <= char.codePointAt(0)! && char.codePointAt(0)! <= high) !== negated
}

// Characters that tend to break a translation into a regular expression: its own syntax, a newline, a character
// outside the BMP (two UTF-16 units), and Python's set operators.
const ODD = ['a', 'b', 'z', '-', '^', '\\', '.', '|', '&', '~', '$', '(', '{', '\n', 'é', '😀']
const char = fc.constantFrom(...ODD, ']', '!')
// Bracket items never hold `]` (it would close the set) and hold `!` only up front: past a dropped range, CPython would
// read a `!` that ends up first as a negation, a quirk the reference above doesn't copy.
const item = fc.constantFrom(...ODD, '[', '*', '?')
const bracket = fc.record({ negated: fc.boolean(), closer: fc.boolean(), items: fc.array(item, { minLength: 1, maxLength: 5 }) })
  .map(({ negated, closer, items }) => `[${negated ? '!' : ''}${closer ? ']' : ''}${items.join('')}]`)
const pattern = fc.tuple(
  fc.array(fc.oneof(char, fc.constant('*'), fc.constant('?'), bracket), { maxLength: 8 }),
  // A `[` never closed is a literal; nothing after it may close it.
  fc.option(fc.array(fc.oneof(char.filter(value => value !== ']'), fc.constant('*'), fc.constant('[')), { maxLength: 3 })),
).map(([tokens, tail]) => tokens.join('') + (tail ? `[${tail.join('')}` : ''))
const text = fc.array(fc.constantFrom(...ODD, ']', '!', '[', '*', '?'), { maxLength: 8 }).map(chars => chars.join(''))

describe('glob patterns of the routing rules', () => {
  it('match exactly what fnmatchcase matches, whatever the characters', () => {
    fc.assert(fc.property(pattern, text, (glob, name) => globMatch(glob, name) === reference(glob, name)), { numRuns: 3000 })
  })

  it('always match the name they were written from', () => {
    // Each character kept, replaced by `?`, put alone in brackets or preceded by `*`.
    const derived = fc.array(fc.tuple(fc.constantFrom(...ODD, ']', '!', '[', '*', '?'), fc.constantFrom('keep', 'any', 'set', 'star')), { maxLength: 8 })
    fc.assert(fc.property(derived, parts => {
      const name = parts.map(([value]) => value).join('')
      const glob = parts.map(([value, how]) => {
        const literal = '*?['.includes(value) || (how === 'set' && value !== '!') ? `[${value}]` : value
        return how === 'any' ? '?' : how === 'star' ? `*${literal}` : literal
      }).join('')
      return globMatch(glob, name)
    }), { numRuns: 1000 })
  })

  it('answers at once for a pattern full of stars', () => {
    // A plain translation backtracks through every way of placing the stars: this one would take hours.
    expect(globMatch(`${'*a'.repeat(12)}*b`, 'a'.repeat(100))).toBe(false)
    expect(globMatch(`${'*a'.repeat(12)}*b`, `${'a'.repeat(100)}b`)).toBe(true)
  })

  it('reads brackets and characters as Python does', () => {
    expect(globMatch('[]a]', ']')).toBe(true)
    expect(globMatch('[!]a]', 'b')).toBe(true)
    expect(globMatch('?', '😀')).toBe(true)
    expect(globMatch('[a-cz-a]', 'b')).toBe(true)
    expect(globMatch('[c-a]', 'b')).toBe(false)
    expect(globMatch('org/[', 'org/[')).toBe(true)
  })
})
