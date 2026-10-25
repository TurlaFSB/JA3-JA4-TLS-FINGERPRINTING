/**
 * © Pranav Verma | 2026
 * sensor-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import { commandFor, nameForCommand, quote } from './sensor-data'

describe('quote', () => {
  it('leaves a plain name alone and quotes anything else', () => {
    expect(quote('eth0')).toBe('eth0')
    expect(quote('Wi-Fi')).toBe('Wi-Fi')
    expect(quote('Intel(R) Wi-Fi 6 AX201')).toBe('"Intel(R) Wi-Fi 6 AX201"')
  })

  it('escapes the characters that stay special inside double quotes', () => {
    expect(quote('a"b$c`d')).toBe('"a\\"b\\$c\\`d"')
  })

  it('builds a paste-able command', () => {
    expect(commandFor('Realtek PCIe GbE')).toBe(
      'tlsfp serve --live "Realtek PCIe GbE"'
    )
  })
})

describe('nameForCommand', () => {
  it('uses the description for a Windows device path and the name otherwise', () => {
    expect(nameForCommand('\\Device\\NPF_{ABC}', 'Intel(R) Ethernet')).toBe(
      'Intel(R) Ethernet'
    )
    expect(nameForCommand('\\Device\\NPF_{ABC}', null)).toBe(
      '\\Device\\NPF_{ABC}'
    )
    expect(nameForCommand('eth0', 'Some NIC')).toBe('eth0')
  })
})
