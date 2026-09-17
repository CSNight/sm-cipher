/*
 * SM3 hash function implementation.
 */

import {concatBytes, copyBytes, readU32BE, rotl32, writeU32BE, writeU64BE,} from "./utils.ts"

const SM3_IV = new Uint32Array([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa,
  0xe38dee4d, 0xb0fb0e4e,
])
const SM3_W = new Uint32Array(68)
const SM3_T = new Uint32Array(64)
for (let i = 0; i < SM3_T.length; i++)
  SM3_T[i] = rotl32(i < 16 ? 0x79cc4519 : 0x7a879d8a, i)

function p0(value: number): number {
  return (value ^ rotl32(value, 9) ^ rotl32(value, 17)) >>> 0
}

function p1(value: number): number {
  return (value ^ rotl32(value, 15) ^ rotl32(value, 23)) >>> 0
}

function ff0(x: number, y: number, z: number): number {
  return (x ^ y ^ z) >>> 0
}

function ff1(x: number, y: number, z: number): number {
  return ((x & y) | (x & z) | (y & z)) >>> 0
}

function gg0(x: number, y: number, z: number): number {
  return (x ^ y ^ z) >>> 0
}

function gg1(x: number, y: number, z: number): number {
  return ((x & y) | (~x & z)) >>> 0
}

function sm3Compress(
  input: Uint8Array,
  offset: number,
  state: Uint32Array
): void {
  const w = SM3_W
  for (let i = 0; i < 16; i++) w[i] = readU32BE(input, offset + i * 4)
  for (let j = 16; j < 68; j++)
    w[j] =
      p1(w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)) ^
      rotl32(w[j - 13], 7) ^
      w[j - 6]

  let a = state[0]
  let b = state[1]
  let c = state[2]
  let d = state[3]
  let e = state[4]
  let f = state[5]
  let g = state[6]
  let h = state[7]
  for (let j = 0; j < 64; j++) {
    const a12 = rotl32(a, 12)
    const ss1 = rotl32((a12 + e + SM3_T[j]) >>> 0, 7)
    const ss2 = ss1 ^ a12
    const tt1 =
      ((j < 16 ? ff0(a, b, c) : ff1(a, b, c)) + d + ss2 + (w[j] ^ w[j + 4])) >>>
      0
    const tt2 = ((j < 16 ? gg0(e, f, g) : gg1(e, f, g)) + h + ss1 + w[j]) >>> 0
    d = c
    c = rotl32(b, 9)
    b = a
    a = tt1
    h = g
    g = rotl32(f, 19)
    f = e
    e = p0(tt2)
  }
  state[0] = (state[0] ^ a) >>> 0
  state[1] = (state[1] ^ b) >>> 0
  state[2] = (state[2] ^ c) >>> 0
  state[3] = (state[3] ^ d) >>> 0
  state[4] = (state[4] ^ e) >>> 0
  state[5] = (state[5] ^ f) >>> 0
  state[6] = (state[6] ^ g) >>> 0
  state[7] = (state[7] ^ h) >>> 0
}

export function sm3Digest(input: Uint8Array): Uint8Array {
  const state = new Uint32Array(SM3_IV)
  const completeLength = input.length - (input.length % 64)
  for (let offset = 0; offset < completeLength; offset += 64)
    sm3Compress(input, offset, state)

  const remaining = input.length - completeLength
  const tail = new Uint8Array(remaining < 56 ? 64 : 128)
  tail.set(input.subarray(completeLength))
  tail[remaining] = 0x80
  writeU64BE(tail, tail.length - 8, BigInt(input.length) * 8n)
  for (let offset = 0; offset < tail.length; offset += 64)
    sm3Compress(tail, offset, state)

  const out = new Uint8Array(32)
  for (let i = 0; i < 8; i++) writeU32BE(out, i * 4, state[i])
  SM3_W.fill(0)
  state.fill(0)
  tail.fill(0)
  return out
}

export function sm3Hmac(
  keyInput: Uint8Array,
  messageInput: Uint8Array
): Uint8Array {
  let key = copyBytes(keyInput, "key")
  const message = copyBytes(messageInput, "message")
  if (key.length > 64) key = sm3Digest(key)
  const block = new Uint8Array(64)
  block.set(key)
  const inner = new Uint8Array(64)
  const outer = new Uint8Array(64)
  for (let i = 0; i < 64; i++) {
    inner[i] = block[i] ^ 0x36
    outer[i] = block[i] ^ 0x5c
  }
  return sm3Digest(concatBytes(outer, sm3Digest(concatBytes(inner, message))))
}

export function sm3(
  input: Uint8Array,
  options?: { key: Uint8Array; mode?: "hmac" }
): Uint8Array {
  if (options && options.mode !== undefined && options.mode !== "hmac")
    throw new Error("invalid mode")
  if (!(input instanceof Uint8Array))
    throw new TypeError("input must be a Uint8Array")
  return options ? sm3Hmac(options.key, input) : sm3Digest(input)
}

export function kdf(z: Uint8Array, length: number): Uint8Array {
  if (Math.ceil(length / 32) > 0xffffffff)
    throw new Error("KDF output is too long")
  const out = new Uint8Array(length)
  let offset = 0
  for (let counter = 1; offset < length; counter++) {
    const ct = new Uint8Array(4)
    ct[0] = counter >>> 24
    ct[1] = counter >>> 16
    ct[2] = counter >>> 8
    ct[3] = counter
    const block = sm3Digest(concatBytes(z, ct))
    const take = Math.min(block.length, length - offset)
    out.set(block.subarray(0, take), offset)
    offset += take
  }
  return out
}
