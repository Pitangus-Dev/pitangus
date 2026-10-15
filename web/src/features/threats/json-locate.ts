// Where things are in a JSON text: the span of every value by its JSON Pointer, or where parsing failed.
// A small strict parser (same grammar as JSON.parse) so problems can point at a line and column.

export type Span = { start: number; end: number }
export type Located = { ok: true; value: unknown; spans: Map<string, Span> } | { ok: false; offset: number; expected: string }

const escapePart = (part: string) => part.replace(/~/g, '~0').replace(/\//g, '~1')

class Failure {
  offset: number
  expected: string
  constructor(offset: number, expected: string) { this.offset = offset; this.expected = expected }
}

export function locate(text: string): Located {
  const spans = new Map<string, Span>()
  let at = 0
  const fail = (expected: string): never => { throw new Failure(at, expected) }
  const space = () => { while (at < text.length && ' \t\n\r'.includes(text[at])) at += 1 }
  const string = (): string => {
    if (text[at] !== '"') fail('"')
    at += 1
    let out = ''
    while (at < text.length) {
      const char = text[at]
      if (char === '"') { at += 1; return out }
      if (char < ' ') fail('"')
      if (char === '\\') {
        const next = text[at + 1]
        const simple: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
        if (next in simple) { out += simple[next]; at += 2; continue }
        if (next === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(at + 2, at + 6))) { out += String.fromCharCode(parseInt(text.slice(at + 2, at + 6), 16)); at += 6; continue }
        at += 1
        fail('escape')
      }
      out += char
      at += 1
    }
    return fail('"')
  }
  const value = (pointer: string): unknown => {
    space()
    const start = at
    let result: unknown
    const char = text[at]
    if (char === '{') {
      at += 1
      const object: Record<string, unknown> = {}
      space()
      if (text[at] === '}') at += 1
      else for (;;) {
        space()
        const key = string()
        space()
        if (text[at] !== ':') fail(':')
        at += 1
        object[key] = value(`${pointer}/${escapePart(key)}`)
        space()
        if (text[at] === ',') { at += 1; continue }
        if (text[at] === '}') { at += 1; break }
        fail(', }')
      }
      result = object
    } else if (char === '[') {
      at += 1
      const array: unknown[] = []
      space()
      if (text[at] === ']') at += 1
      else for (;;) {
        array.push(value(`${pointer}/${array.length}`))
        space()
        if (text[at] === ',') { at += 1; continue }
        if (text[at] === ']') { at += 1; break }
        fail(', ]')
      }
      result = array
    } else if (char === '"') result = string()
    else {
      const literal = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(at))
      if (!literal) fail('value')
      at += literal![0].length
      result = JSON.parse(literal![0]) as unknown
    }
    spans.set(pointer, { start, end: at })
    return result
  }
  try {
    const parsed = value('')
    space()
    if (at < text.length) fail('end')
    return { ok: true, value: parsed, spans }
  } catch (caught) {
    if (caught instanceof Failure) return { ok: false, offset: Math.min(caught.offset, text.length), expected: caught.expected }
    throw caught
  }
}

// The closest span for a pointer: the value itself or, when it is missing (a required field), its nearest parent.
export function spanOf(spans: Map<string, Span>, pointer: string): Span | null {
  let current = pointer
  for (;;) {
    const span = spans.get(current)
    if (span) return span
    if (!current) return null
    current = current.slice(0, current.lastIndexOf('/'))
  }
}

export function lineColumn(text: string, offset: number) {
  const before = text.slice(0, offset)
  const line = before.split('\n').length
  return { line, column: offset - before.lastIndexOf('\n') }
}
