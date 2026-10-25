/**
 * © Pranav Verma | 2026
 * export.test.ts
 */

import { describe, expect, it } from 'vitest'
import { toCsv } from './export'

describe('toCsv', () => {
  it('quotes commas, quotes and newlines', () => {
    expect(toCsv(['a', 'b'], [['x,y', 'say "hi"\nthere']])).toBe(
      'a,b\r\n"x,y","say ""hi""\nthere"\r\n'
    )
  })

  it('turns a leading formula character into text', () => {
    const csv = toCsv(
      ['v'],
      [['=HYPERLINK("http://evil")'], ['+1'], ['-1'], ['@sum']]
    )
    for (const line of csv.trim().split('\r\n').slice(1)) {
      expect(line.replace(/^"/, '').startsWith("'")).toBe(true)
    }
  })

  it('writes empty cells for null and undefined and keeps numbers', () => {
    expect(toCsv(['a', 'b', 'c'], [[null, undefined, 3]])).toBe(
      'a,b,c\r\n,,3\r\n'
    )
  })
})
