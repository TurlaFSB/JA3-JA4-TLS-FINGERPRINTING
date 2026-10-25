/**
 * © Pranav Verma | 2026
 * sensor-data.ts
 */

// Quotes a value for a command line the operator will paste: anything with a
// character the shell or PowerShell treats specially goes inside double
// quotes, with the characters that matter inside them escaped.
export function quote(value: string): string {
  if (/^[A-Za-z0-9._:/@-]+$/.test(value)) return value
  return `"${value.replace(/(["\\$`])/g, '\\$1')}"`
}

export function commandFor(interfaceName: string): string {
  return `tlsfp serve --live ${quote(interfaceName)}`
}

// The name to put in a command. On Windows the real names are
// `\\Device\\NPF_{GUID}`, which nobody types; the description matches too.
export function nameForCommand(name: string, description: string | null): string {
  return name.startsWith('\\Device\\') && description ? description : name
}
