/*
 * SM4 block cipher implementation.
 */

import {
  concatBytes,
  copyBytes,
  equalBytes,
  readU32BE,
  rotl32,
  writeU32BE,
  writeU64BE,
  xorBytes,
} from "./utils.ts"
import type { GCMResult, SM4Options } from "./types.ts"

const SM4_SBOX = Uint8Array.from([
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28,
  0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44,
  0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98,
  0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9,
  0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47,
  0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85,
  0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f,
  0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
  0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f,
  0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf,
  0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15,
  0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
  0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0,
  0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd,
  0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf,
  0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8,
  0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9,
  0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d,
  0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
])
const SM4_CK = new Uint32Array([
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
  0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
  0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
  0x484f565d, 0x646b7279,
])

const EMPTY = new Uint8Array(0)

function sm4Sub(value: number): number {
  return (
    ((SM4_SBOX[value >>> 24] << 24) |
      (SM4_SBOX[(value >>> 16) & 255] << 16) |
      (SM4_SBOX[(value >>> 8) & 255] << 8) |
      SM4_SBOX[value & 255]) >>>
    0
  )
}

function sm4L(value: number): number {
  return (
    (value ^
      rotl32(value, 2) ^
      rotl32(value, 10) ^
      rotl32(value, 18) ^
      rotl32(value, 24)) >>>
    0
  )
}

function sm4LKey(value: number): number {
  return (value ^ rotl32(value, 13) ^ rotl32(value, 23)) >>> 0
}

// T-table: merges Sbox substitution with the L linear transform.
// T0[b] = L(Sbox[b] << 24), T1[b] = L(Sbox[b] << 16), etc. — one lookup
// per input byte replaces a byte-substitution followed by 5 rotate/xor ops.
// This is the standard SPN acceleration technique gmsm also uses for SM4.
const SM4_T0 = new Uint32Array(256)
const SM4_T1 = new Uint32Array(256)
const SM4_T2 = new Uint32Array(256)
const SM4_T3 = new Uint32Array(256)
for (let b = 0; b < 256; b++) {
  const sub = SM4_SBOX[b]
  const t0 = sm4L(sub << 24)
  SM4_T0[b] = t0
  SM4_T1[b] = rotl32(t0, 24)
  SM4_T2[b] = rotl32(t0, 16)
  SM4_T3[b] = rotl32(t0, 8)
}

function sm4TRound(value: number): number {
  return (
    (SM4_T0[value >>> 24] ^
      SM4_T1[(value >>> 16) & 255] ^
      SM4_T2[(value >>> 8) & 255] ^
      SM4_T3[value & 255]) >>>
    0
  )
}

function sm4RoundKeys(key: Uint8Array, decrypt: boolean): Uint32Array {
  let x0 = readU32BE(key, 0) ^ 0xa3b1bac6
  let x1 = readU32BE(key, 4) ^ 0x56aa3350
  let x2 = readU32BE(key, 8) ^ 0x677d9197
  let x3 = readU32BE(key, 12) ^ 0xb27022dc
  const keys = new Uint32Array(32)
  for (let i = 0; i < 32; i += 4) {
    x0 = (x0 ^ sm4LKey(sm4Sub(x1 ^ x2 ^ x3 ^ SM4_CK[i]))) >>> 0
    keys[i] = x0
    x1 = (x1 ^ sm4LKey(sm4Sub(x2 ^ x3 ^ x0 ^ SM4_CK[i + 1]))) >>> 0
    keys[i + 1] = x1
    x2 = (x2 ^ sm4LKey(sm4Sub(x3 ^ x0 ^ x1 ^ SM4_CK[i + 2]))) >>> 0
    keys[i + 2] = x2
    x3 = (x3 ^ sm4LKey(sm4Sub(x0 ^ x1 ^ x2 ^ SM4_CK[i + 3]))) >>> 0
    keys[i + 3] = x3
  }
  if (decrypt) keys.reverse()
  return keys
}

function sm4Block(
  input: Uint8Array,
  output: Uint8Array,
  keys: Uint32Array,
  inputOffset = 0,
  outputOffset = 0
): void {
  let x0 = readU32BE(input, inputOffset)
  let x1 = readU32BE(input, inputOffset + 4)
  let x2 = readU32BE(input, inputOffset + 8)
  let x3 = readU32BE(input, inputOffset + 12)
  for (let i = 0; i < 32; i += 4) {
    x0 = (x0 ^ sm4TRound(x1 ^ x2 ^ x3 ^ keys[i])) >>> 0
    x1 = (x1 ^ sm4TRound(x2 ^ x3 ^ x0 ^ keys[i + 1])) >>> 0
    x2 = (x2 ^ sm4TRound(x3 ^ x0 ^ x1 ^ keys[i + 2])) >>> 0
    x3 = (x3 ^ sm4TRound(x0 ^ x1 ^ x2 ^ keys[i + 3])) >>> 0
  }
  writeU32BE(output, outputOffset, x3)
  writeU32BE(output, outputOffset + 4, x2)
  writeU32BE(output, outputOffset + 8, x1)
  writeU32BE(output, outputOffset + 12, x0)
}

function sm4Key(input: Uint8Array): Uint8Array {
  const key = copyBytes(input, "key")
  if (key.length !== 16) throw new Error("key is invalid")
  return key
}

function sm4Iv(input: Uint8Array | undefined): Uint8Array {
  const iv = input === undefined ? new Uint8Array(16) : copyBytes(input, "iv")
  if (iv.length !== 16) throw new Error("iv is invalid")
  return iv
}

// Adapted noble GHASH window table. All words use explicit big-endian loads:
// unaligned/subarray inputs never depend on host byte order or buffer alignment.
function ghashTable(h: Uint8Array): Uint32Array {
  const doubles = new Uint32Array(128 * 4)
  let a = readU32BE(h, 0)
  let b = readU32BE(h, 4)
  let c = readU32BE(h, 8)
  let d = readU32BE(h, 12)
  for (let i = 0; i < 128; i++) {
    doubles.set([a, b, c, d], i * 4)
    const carry = d & 1
    d = ((c << 31) | (d >>> 1)) >>> 0
    c = ((b << 31) | (c >>> 1)) >>> 0
    b = ((a << 31) | (b >>> 1)) >>> 0
    a = ((a >>> 1) ^ (carry ? 0xe1000000 : 0)) >>> 0
  }
  const table = new Uint32Array(32 * 16 * 4)
  for (let window = 0; window < 32; window++) {
    for (let value = 0; value < 16; value++) {
      const offset = (window * 16 + value) * 4
      for (let bit = 0; bit < 4; bit++) {
        if (!(value & (1 << (3 - bit)))) continue
        const source = (window * 4 + bit) * 4
        for (let word = 0; word < 4; word++)
          table[offset + word] ^= doubles[source + word]
      }
    }
  }
  doubles.fill(0)
  return table
}

function ghashSegments(table: Uint32Array, segments: Uint8Array[]): Uint8Array {
  const state = new Uint32Array(4)
  const words = new Uint32Array(4)
  const tail = new Uint8Array(16)
  for (const segment of segments) {
    for (let offset = 0; offset < segment.length; offset += 16) {
      let block = segment.subarray(offset, offset + 16)
      if (block.length < 16) {
        tail.fill(0)
        tail.set(block)
        block = tail
      }
      for (let i = 0; i < 4; i++) words[i] = state[i] ^ readU32BE(block, i * 4)
      state.fill(0)
      for (let window = 0; window < 32; window++) {
        const value = (words[window >>> 3] >>> (28 - (window & 7) * 4)) & 15
        const source = (window * 16 + value) * 4
        for (let i = 0; i < 4; i++) state[i] ^= table[source + i]
      }
    }
  }
  const out = new Uint8Array(16)
  for (let i = 0; i < 4; i++) writeU32BE(out, i * 4, state[i])
  state.fill(0)
  words.fill(0)
  tail.fill(0)
  return out
}

/** Each segment is independently zero-padded to a 16-byte boundary. */
export function sm4Ghash(h: Uint8Array, ...segments: Uint8Array[]): Uint8Array {
  if (!(h instanceof Uint8Array) || h.length !== 16)
    throw new Error("Invalid GHASH key")
  for (const segment of segments)
    if (!(segment instanceof Uint8Array)) throw new Error("Invalid GHASH input")
  const table = ghashTable(h)
  try {
    return ghashSegments(table, segments)
  } finally {
    table.fill(0)
  }
}

function increment32(counter: Uint8Array): void {
  for (let i = 15; i >= 12; i--) {
    counter[i] = (counter[i] + 1) & 255
    if (counter[i] !== 0) break
  }
}

function sm4Gcm(
  input: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  decrypt: boolean,
  tag?: Uint8Array
): {
  output: Uint8Array
  tag: Uint8Array
} {
  if (iv.length === 0 || input.length > 0xfffffffe * 16)
    throw new Error("Invalid GCM length")
  if (decrypt && (!tag || tag.length !== 16))
    throw new Error("authentication failed")
  const keys = sm4RoundKeys(key, false)
  const hBlock = new Uint8Array(16)
  sm4Block(new Uint8Array(16), hBlock, keys)
  const table = ghashTable(hBlock)
  let j0: Uint8Array
  if (iv.length === 12) j0 = concatBytes(iv, Uint8Array.of(0, 0, 0, 1))
  else {
    const ivLength = new Uint8Array(16)
    writeU64BE(ivLength, 8, BigInt(iv.length) * 8n)
    j0 = ghashSegments(table, [iv, ivLength])
  }
  const lengths = new Uint8Array(16)
  writeU64BE(lengths, 0, BigInt(aad.length) * 8n)
  writeU64BE(lengths, 8, BigInt(input.length) * 8n)
  const mask = new Uint8Array(16)
  sm4Block(j0, mask, keys)
  if (decrypt) {
    const auth = xorBytes(mask, ghashSegments(table, [aad, input, lengths]))
    if (!equalBytes(auth, tag!)) {
      table.fill(0)
      keys.fill(0)
      throw new Error("authentication failed")
    }
  }
  const counter = new Uint8Array(j0)
  increment32(counter)
  const output = new Uint8Array(input.length)
  const stream = new Uint8Array(16)
  for (let offset = 0; offset < input.length; offset += 16) {
    sm4Block(counter, stream, keys)
    const length = Math.min(16, input.length - offset)
    for (let i = 0; i < length; i++)
      output[offset + i] = input[offset + i] ^ stream[i]
    increment32(counter)
  }
  const auth = decrypt
    ? new Uint8Array(tag!)
    : xorBytes(mask, ghashSegments(table, [aad, output, lengths]))
  table.fill(0)
  keys.fill(0)
  hBlock.fill(0)
  stream.fill(0)
  return { output, tag: auth }
}

function sm4BlockMode(
  input: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  decrypt: boolean,
  mode: "cbc" | "ecb",
  padding: SM4Options["padding"]
): Uint8Array {
  if (
    padding !== undefined &&
    padding !== null &&
    padding !== "pkcs#5" &&
    padding !== "pkcs#7" &&
    padding !== "none"
  )
    throw new Error("padding is invalid")
  let data = input
  if (
    !decrypt &&
    (padding === "pkcs#5" || padding === "pkcs#7" || padding === undefined)
  ) {
    const count = 16 - (data.length % 16)
    const padded = new Uint8Array(data.length + count)
    padded.set(data)
    padded.fill(count, data.length)
    data = padded
  } else if (
    !decrypt &&
    padding !== "none" &&
    padding !== null &&
    padding !== undefined
  )
    throw new Error("padding is invalid")
  if (data.length % 16 !== 0) throw new Error("input length is invalid")
  const keys = sm4RoundKeys(key, decrypt)
  const output = new Uint8Array(data.length)
  const block = mode === "cbc" && !decrypt ? new Uint8Array(16) : undefined
  for (let offset = 0; offset < data.length; offset += 16) {
    if (mode === "ecb") sm4Block(data, output, keys, offset, offset)
    else if (decrypt) {
      sm4Block(data, output, keys, offset, offset)
      for (let i = 0; i < 16; i++)
        output[offset + i] ^= offset === 0 ? iv[i] : data[offset - 16 + i]
    } else {
      for (let i = 0; i < 16; i++)
        block![i] =
          data[offset + i] ^ (offset === 0 ? iv[i] : output[offset - 16 + i])
      sm4Block(block!, output, keys, 0, offset)
    }
  }
  block?.fill(0)
  if (
    decrypt &&
    (padding === "pkcs#5" || padding === "pkcs#7" || padding === undefined)
  ) {
    if (output.length === 0) throw new Error("padding is invalid")
    const count = output[output.length - 1]
    if (count < 1 || count > 16 || count > output.length)
      throw new Error("padding is invalid")
    for (let i = 1; i <= count; i++)
      if (output[output.length - i] !== count)
        throw new Error("padding is invalid")
    return output.slice(0, output.length - count)
  }
  return output
}

function sm4Transform(
  inArray: Uint8Array,
  keyInput: Uint8Array,
  cryptFlag: 0 | 1,
  options: SM4Options = {}
): Uint8Array | GCMResult {
  const decrypt = cryptFlag === 0
  const mode = options.mode || "ecb"
  const key = sm4Key(keyInput)
  const input = copyBytes(inArray)
  if (mode === "gcm") {
    const iv =
      options.iv === undefined
        ? new Uint8Array(16)
        : copyBytes(options.iv, "iv")
    const aad =
      options.associatedData === undefined
        ? EMPTY
        : copyBytes(options.associatedData, "associatedData")
    const tag =
      options.tag === undefined ? undefined : copyBytes(options.tag, "tag")
    const result = sm4Gcm(input, key, iv, aad, decrypt, tag)
    return decrypt ? result.output : result
  }
  if (mode !== "cbc" && mode !== "ecb") throw new Error("mode is invalid")
  return sm4BlockMode(
    input,
    key,
    mode === "cbc" ? sm4Iv(options.iv) : new Uint8Array(16),
    decrypt,
    mode,
    options.padding
  )
}

export function sm4Encrypt(
  inArray: Uint8Array,
  key: Uint8Array,
  options: SM4Options & { mode: "gcm" }
): GCMResult
export function sm4Encrypt(
  inArray: Uint8Array,
  key: Uint8Array,
  options?: SM4Options & {
    mode?: "ecb" | "cbc"
  }
): Uint8Array
export function sm4Encrypt(
  inArray: Uint8Array,
  key: Uint8Array,
  options?: SM4Options
): Uint8Array | GCMResult
export function sm4Encrypt(
  inArray: Uint8Array,
  key: Uint8Array,
  options?: SM4Options
): Uint8Array | GCMResult {
  return sm4Transform(inArray, key, 1, options)
}

export function sm4Decrypt(
  inArray: Uint8Array,
  key: Uint8Array,
  options?: SM4Options
): Uint8Array {
  return sm4Transform(inArray, key, 0, options) as Uint8Array
}
