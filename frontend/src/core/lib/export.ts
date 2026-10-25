/**
 * © Pranav Verma | 2026
 * export.ts
 */

// A spreadsheet runs a cell that starts with one of these as a formula, and a
// fingerprinted network is hostile: a name or User-Agent can be chosen by an
// attacker. Prefixing the cell with a quote makes it text.
const FORMULA_START = /^[=+\-@\t\r]/

function cell(value: unknown): string {
  let text = value === null || value === undefined ? '' : String(value)
  if (FORMULA_START.test(text)) text = `'${text}`
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export function toCsv(
  headers: string[],
  rows: (string | number | boolean | null | undefined)[][]
): string {
  const lines = [headers, ...rows].map((row) => row.map(cell).join(','))
  return `${lines.join('\r\n')}\r\n`
}

export function downloadText(filename: string, mime: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.append(link)
  link.click()
  link.remove()
  // Revoke after the click has been handled.
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function stamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
}
