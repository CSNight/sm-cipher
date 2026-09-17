/*
 * Shared utility functions for smcrypto.
 */

import type {RandomSource} from './types.ts'

let customRandomSource: RandomSource | undefined

export function setRandomSource(source?: RandomSource): void {
    if (source !== undefined && typeof source !== 'function') throw new TypeError('random source must be a function')
    customRandomSource = source
}

export function randomBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) throw new Error('Invalid random byte length')
    if (customRandomSource) {
        const out = customRandomSource(length)
        if (!(out instanceof Uint8Array) || out.length !== length) throw new Error('Random source returned invalid bytes')
        return new Uint8Array(out)
    }
    const crypto = (globalThis as { crypto?: Crypto }).crypto
    if (!crypto?.getRandomValues) throw new Error('A secure random source is required')
    const out = new Uint8Array(length)
    crypto.getRandomValues(out)
    return out
}

export function copyBytes(input: Uint8Array, name = 'input'): Uint8Array {
    if (!(input instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array`)
    return new Uint8Array(input)
}

export function utf8ToBytes(input: string): Uint8Array {
    if (typeof input !== 'string') throw new TypeError('input must be a string')
    const out: number[] = []
    for (let i = 0; i < input.length; i++) {
        let cp = input.codePointAt(i)!
        if (cp > 0xffff) i++
        if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd
        if (cp <= 0x7f) out.push(cp)
        else if (cp <= 0x7ff) out.push(0xc0 | (cp >>> 6), 0x80 | (cp & 0x3f))
        else if (cp <= 0xffff) out.push(0xe0 | (cp >>> 12), 0x80 | ((cp >>> 6) & 0x3f), 0x80 | (cp & 0x3f))
        else out.push(0xf0 | (cp >>> 18), 0x80 | ((cp >>> 12) & 0x3f), 0x80 | ((cp >>> 6) & 0x3f), 0x80 | (cp & 0x3f))
    }
    return Uint8Array.from(out)
}

export function bytesToUtf8(bytes: Uint8Array): string {
    const input = copyBytes(bytes)
    let output = ''
    for (let i = 0; i < input.length;) {
        const first = input[i++]
        let codePoint: number
        if (first <= 0x7f) codePoint = first
        else if (first >= 0xc2 && first <= 0xdf) {
            if (i >= input.length || (input[i] & 0xc0) !== 0x80) throw new Error('Malformed UTF-8 data')
            codePoint = ((first & 0x1f) << 6) | (input[i++] & 0x3f)
        } else if (first >= 0xe0 && first <= 0xef) {
            if (i + 1 >= input.length || (input[i] & 0xc0) !== 0x80 || (input[i + 1] & 0xc0) !== 0x80) throw new Error('Malformed UTF-8 data')
            const second = input[i++]
            if ((first === 0xe0 && second < 0xa0) || (first === 0xed && second >= 0xa0)) throw new Error('Malformed UTF-8 data')
            codePoint = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (input[i++] & 0x3f)
        } else if (first >= 0xf0 && first <= 0xf4) {
            if (i + 2 >= input.length || (input[i] & 0xc0) !== 0x80 || (input[i + 1] & 0xc0) !== 0x80 || (input[i + 2] & 0xc0) !== 0x80) throw new Error('Malformed UTF-8 data')
            const second = input[i++]
            if ((first === 0xf0 && second < 0x90) || (first === 0xf4 && second >= 0x90)) throw new Error('Malformed UTF-8 data')
            codePoint = ((first & 0x07) << 18) | ((second & 0x3f) << 12) | ((input[i++] & 0x3f) << 6) | (input[i++] & 0x3f)
        } else throw new Error('Malformed UTF-8 data')
        output += String.fromCodePoint(codePoint)
    }
    return output
}

export function hexToBytes(hex: string): Uint8Array {
    if (typeof hex !== 'string' || (hex.length & 1) !== 0 || !/^[0-9a-f]*$/i.test(hex)) throw new Error('Invalid hexadecimal input')
    const out = new Uint8Array(hex.length >>> 1)
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return out
}

export function bytesToHex(bytes: Uint8Array): string {
    const input = copyBytes(bytes)
    const out = new Array<string>(input.length)
    for (let i = 0; i < input.length; i++) out[i] = input[i].toString(16).padStart(2, '0')
    return out.join('')
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    let length = 0
    for (const part of parts) length += copyBytes(part).length
    const out = new Uint8Array(length)
    let offset = 0
    for (const part of parts) {
        out.set(part, offset)
        offset += part.length
    }
    return out
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length !== b.length) throw new Error('Byte arrays have different lengths')
    const out = new Uint8Array(a.length)
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i]
    return out
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
    return diff === 0
}

export function readU32BE(input: Uint8Array, offset: number): number {
    return ((input[offset] << 24) | (input[offset + 1] << 16) | (input[offset + 2] << 8) | input[offset + 3]) >>> 0
}

export function writeU32BE(input: Uint8Array, offset: number, value: number): void {
    input[offset] = value >>> 24
    input[offset + 1] = value >>> 16
    input[offset + 2] = value >>> 8
    input[offset + 3] = value
}

export function writeU64BE(input: Uint8Array, offset: number, value: bigint): void {
    for (let i = 7; i >= 0; i--) {
        input[offset + i] = Number(value & 0xffn)
        value >>= 8n
    }
}

export function rotl32(value: number, count: number): number {
    count &= 31
    return count === 0 ? value >>> 0 : ((value << count) | (value >>> (32 - count))) >>> 0
}
