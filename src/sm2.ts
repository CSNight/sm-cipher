/*
 * SM2 elliptic curve cryptography implementation.
 */

import {concatBytes, copyBytes, equalBytes, hexToBytes, randomBytes, utf8ToBytes, xorBytes,} from "./utils.ts"
import {kdf, sm3Digest} from "./sm3.ts"
import type {PrecomputedPublicKey, PublicKey, SignaturePoint, Sm2CipherOptions, SM2Mode,} from "./types.ts"

export const C1C2C3 = 0 as SM2Mode
export const C1C3C2 = 1 as SM2Mode
export const SM2CipherMode = Object.freeze({C1C2C3, C1C3C2})

const P = BigInt(
  "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
)
const A = BigInt(
  "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
)
const B = BigInt(
  "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
)
const N = BigInt(
  "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
)
const GX = BigInt(
  "0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
)
const GY = BigInt(
  "0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
)
const G = {x: GX, y: GY, z: 1n}
type JacobianPoint = { x: bigint; y: bigint; z: bigint }
type AffinePoint = { x: bigint; y: bigint }
type ResolvedPublicKey = {
  point: JacobianPoint
  publicKey: Uint8Array
  table?: JacobianPoint[][]
  windowSize?: number
}
const precomputedPublicKeys = new WeakMap<
  PrecomputedPublicKey,
  ResolvedPublicKey
>()

const INF: JacobianPoint = {x: 0n, y: 1n, z: 0n}

function mod(value: bigint): bigint {
  const result = value % P
  return result < 0n ? result + P : result
}

function modN(value: bigint): bigint {
  const result = value % N
  return result < 0n ? result + N : result
}

function inverse(value: bigint, modulus: bigint): bigint {
  let a = value % modulus
  if (a < 0n) a += modulus
  let b = modulus
  let x0 = 1n
  let x1 = 0n
  while (b !== 0n) {
    const q = a / b
    ;[a, b] = [b, a - q * b]
    ;[x0, x1] = [x1, x0 - q * x1]
  }
  if (a !== 1n) throw new Error("Inverse does not exist")
  return x0 < 0n ? x0 + modulus : x0
}

function pointDouble(point: JacobianPoint): JacobianPoint {
  if (point.z === 0n || point.y === 0n) return INF
  const yy = mod(point.y * point.y)
  const yyyy = mod(yy * yy)
  const zz = mod(point.z * point.z)
  const zzzz = mod(zz * zz)
  const s = mod(4n * point.x * yy)
  const m = mod(3n * point.x * point.x + A * zzzz)
  const nx = mod(m * m - 2n * s)
  const ny = mod(m * (s - nx) - 8n * yyyy)
  const nz = mod(2n * point.y * point.z)
  return {x: nx, y: ny, z: nz}
}

function pointAdd(one: JacobianPoint, two: JacobianPoint): JacobianPoint {
  if (one.z === 0n) return two
  if (two.z === 0n) return one
  const z1z1 = mod(one.z * one.z)
  const z2z2 = mod(two.z * two.z)
  const u1 = mod(one.x * z2z2)
  const u2 = mod(two.x * z1z1)
  const s1 = mod(one.y * two.z * z2z2)
  const s2 = mod(two.y * one.z * z1z1)
  if (u1 === u2) return s1 === s2 ? pointDouble(one) : INF
  const h = mod(u2 - u1)
  const r = mod(s2 - s1)
  const hh = mod(h * h)
  const hhh = mod(h * hh)
  const v = mod(u1 * hh)
  return {
    x: mod(r * r - hhh - 2n * v),
    y: mod(r * (v - mod(r * r - hhh - 2n * v)) - s1 * hhh),
    z: mod(h * one.z * two.z),
  }
}

function pointToAffine(point: JacobianPoint): AffinePoint {
  if (point.z === 0n) throw new Error("Point at infinity")
  const zi = inverse(point.z, P)
  const zi2 = mod(zi * zi)
  return {x: mod(point.x * zi2), y: mod(point.y * zi2 * zi)}
}

function scalarMultiply(point: JacobianPoint, scalar: bigint): JacobianPoint {
  if (scalar === 0n || point.z === 0n) return INF
  let result = INF
  let addend = point
  let value = scalar
  while (value > 0n) {
    if (value & 1n) result = pointAdd(result, addend)
    addend = pointDouble(addend)
    value >>= 1n
  }
  return result
}

const BASE_WINDOW_BITS = 5
let baseTable: JacobianPoint[][] | undefined

function pointNegate(point: JacobianPoint): JacobianPoint {
  return point.z === 0n
    ? INF
    : {x: point.x, y: point.y === 0n ? 0n : P - point.y, z: point.z}
}

function createFixedWindowTable(
  point: JacobianPoint,
  windowSize: number
): JacobianPoint[][] {
  const half = 1 << (windowSize - 1)
  const windowCount = Math.ceil(256 / windowSize) + 1
  const table: JacobianPoint[][] = []
  let base = point
  for (let window = 0; window < windowCount; window++) {
    const multiples = [INF, base]
    for (let digit = 2; digit <= half; digit++)
      multiples.push(pointAdd(multiples[digit - 1], base))
    table.push(multiples)
    for (let bit = 0; bit < windowSize; bit++) base = pointDouble(base)
  }
  return table
}

function scalarMultiplyWindow(
  table: JacobianPoint[][],
  windowSize: number,
  scalar: bigint
): JacobianPoint {
  const radix = 1 << windowSize
  const half = radix >>> 1
  const shift = BigInt(windowSize)
  const mask = (1n << shift) - 1n
  let result = INF
  let value = scalar
  let window = 0
  while (value > 0n) {
    let digit = Number(value & mask)
    if (digit > half) digit -= radix
    if (digit !== 0) {
      const point = table[window][Math.abs(digit)]
      result = pointAdd(result, digit < 0 ? pointNegate(point) : point)
    }
    value = (value - BigInt(digit)) >> shift
    window++
  }
  return result
}

function getBaseTable(): JacobianPoint[][] {
  if (!baseTable) baseTable = createFixedWindowTable(G, BASE_WINDOW_BITS)
  return baseTable
}

function scalarMultiplyBase(scalar: bigint): JacobianPoint {
  return scalarMultiplyWindow(getBaseTable(), BASE_WINDOW_BITS, scalar)
}

function bigintToFixed(value: bigint, length = 64): string {
  const hex = value.toString(16)
  if (hex.length > length) throw new Error("Integer is too large")
  return hex.padStart(length, "0")
}

function bigintToBytes(value: bigint, length = 32): Uint8Array {
  return hexToBytes(bigintToFixed(value, length * 2))
}

function parsePrivateKey(privateKey: Uint8Array): bigint {
  const bytes = copyBytes(privateKey, "privateKey")
  if (bytes.length !== 32) throw new Error("Invalid private key")
  const value = bytesToBigInt(bytes)
  if (value <= 0n || value >= N) throw new Error("Invalid private key")
  return value
}

function affineToJacobian(point: AffinePoint): JacobianPoint {
  return {x: point.x, y: point.y, z: 1n}
}

function sqrtMod(value: bigint): bigint {
  const result = modPow(value, (P + 1n) >> 2n, P)
  if (mod(result * result - value) !== 0n) throw new Error("Invalid public key")
  return result
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n
  let value = base % modulus
  let power = exponent
  while (power > 0n) {
    if (power & 1n) result = (result * value) % modulus
    value = (value * value) % modulus
    power >>= 1n
  }
  return result
}

function decodePublicKey(publicKey: Uint8Array): AffinePoint {
  const bytes = copyBytes(publicKey, "publicKey")
  const prefix = bytes[0]
  let x: bigint
  let y: bigint
  if (prefix === 0x04) {
    if (bytes.length !== 65) throw new Error("Invalid public key")
    x = bytesToBigInt(bytes.subarray(1, 33))
    y = bytesToBigInt(bytes.subarray(33))
  } else if (prefix === 0x02 || prefix === 0x03) {
    if (bytes.length !== 33) throw new Error("Invalid public key")
    x = bytesToBigInt(bytes.subarray(1))
    const rhs = mod(x * x * x + A * x + B)
    y = sqrtMod(rhs)
    if (Number(y & 1n) !== Number(prefix === 0x03)) y = P - y
  } else throw new Error("Invalid public key")
  if (x >= P || y >= P || mod(y * y - (x * x * x + A * x + B)) !== 0n)
    throw new Error("Invalid public key")
  return {x, y}
}

function resolvePublicKey(publicKey: PublicKey): ResolvedPublicKey {
  if (publicKey instanceof Uint8Array) {
    const decoded = decodePublicKey(publicKey)
    const canonical = encodePublicKey(decoded)
    return {
      point: affineToJacobian(decoded),
      publicKey: canonical,
    }
  }
  const resolved = precomputedPublicKeys.get(publicKey)
  if (!resolved) throw new Error("Invalid precomputed public key")
  return resolved
}

function multiplyPublicKey(
  publicKey: ResolvedPublicKey,
  scalar: bigint
): JacobianPoint {
  return publicKey.table
    ? scalarMultiplyWindow(publicKey.table, publicKey.windowSize!, scalar)
    : scalarMultiply(publicKey.point, scalar)
}

function publicKeyBytes(publicKey: PublicKey): Uint8Array {
  return new Uint8Array(resolvePublicKey(publicKey).publicKey)
}

function encodePublicKey(point: AffinePoint): Uint8Array {
  return concatBytes(
    Uint8Array.of(0x04),
    bigintToBytes(point.x),
    bigintToBytes(point.y)
  )
}

export function precomputePublicKey(
  publicKey: Uint8Array,
  windowSize = 4
): PrecomputedPublicKey {
  if (!Number.isInteger(windowSize) || windowSize < 2 || windowSize > 8)
    throw new Error("Invalid window size")
  const point = affineToJacobian(decodePublicKey(publicKey))
  const table = createFixedWindowTable(point, windowSize)
  const canonical = encodePublicKey(pointToAffine(point))
  const prepared = Object.freeze({
    get publicKey() {
      return new Uint8Array(canonical)
    },
    windowSize,
  })
  precomputedPublicKeys.set(prepared, {
    point,
    publicKey: canonical,
    table,
    windowSize,
  })
  return prepared
}

function randomScalar(): bigint {
  while (true) {
    const candidate = bytesToBigInt(randomBytes(32))
    if (candidate > 0n && candidate < N) return candidate
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

export function generateKeyPair(seed?: Uint8Array): {
  privateKey: Uint8Array
  publicKey: Uint8Array
} {
  let privateKey: bigint
  if (seed !== undefined) {
    const seedBytes = copyBytes(seed, "seed")
    if (seedBytes.length === 0) throw new Error("Invalid seed")
    privateKey = (bytesToBigInt(seedBytes) % (N - 1n)) + 1n
  } else privateKey = randomScalar()
  const point = pointToAffine(scalarMultiplyBase(privateKey))
  return {
    privateKey: bigintToBytes(privateKey),
    publicKey: encodePublicKey(point),
  }
}

export function getPublicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array {
  const point = pointToAffine(scalarMultiplyBase(parsePrivateKey(privateKey)))
  return encodePublicKey(point)
}

export function compressPublicKey(publicKey: Uint8Array): Uint8Array {
  const point = decodePublicKey(publicKey)
  return concatBytes(
    Uint8Array.of((point.y & 1n) === 0n ? 0x02 : 0x03),
    bigintToBytes(point.x)
  )
}

export function verifyPublicKey(publicKey: Uint8Array): boolean {
  try {
    decodePublicKey(publicKey)
    return true
  } catch {
    return false
  }
}

export function comparePublicKey(one: Uint8Array, two: Uint8Array): boolean {
  try {
    const a = decodePublicKey(one)
    const b = decodePublicKey(two)
    return a.x === b.x && a.y === b.y
  } catch {
    return false
  }
}

export function getPoint(): SignaturePoint {
  const k = randomScalar()
  const point = pointToAffine(scalarMultiplyBase(k))
  return {
    k: bigintToBytes(k),
    x1: bigintToBytes(point.x),
    privateKey: bigintToBytes(k),
    publicKey: encodePublicKey(point),
  }
}

export function getHash(
  message: Uint8Array,
  publicKey: Uint8Array,
  userId = utf8ToBytes("1234567812345678")
): Uint8Array {
  const data = copyBytes(message, "message")
  const uid = copyBytes(userId, "userId")
  if (uid.length > 8191) throw new Error("userId is too long")
  const point = decodePublicKey(publicKey)
  const entl = new Uint8Array([uid.length >>> 5, (uid.length << 3) & 0xff])
  const parameters = concatBytes(
    entl,
    uid,
    hexToBytes(bigintToFixed(A)),
    hexToBytes(bigintToFixed(B)),
    hexToBytes(bigintToFixed(GX)),
    hexToBytes(bigintToFixed(GY)),
    hexToBytes(bigintToFixed(point.x)),
    hexToBytes(bigintToFixed(point.y))
  )
  return sm3Digest(concatBytes(sm3Digest(parameters), data))
}

function sm2C1(publicPoint: AffinePoint): Uint8Array {
  return concatBytes(
    hexToBytes(bigintToFixed(publicPoint.x)),
    hexToBytes(bigintToFixed(publicPoint.y))
  )
}

function sm2EncryptBytes(
  message: Uint8Array,
  publicKey: PublicKey
): {
  c1: Uint8Array
  c2: Uint8Array
  c3: Uint8Array
} {
  const recipient = resolvePublicKey(publicKey)
  while (true) {
    const k = randomScalar()
    const c1Point = pointToAffine(scalarMultiplyBase(k))
    const shared = pointToAffine(multiplyPublicKey(recipient, k))
    const x2 = hexToBytes(bigintToFixed(shared.x))
    const y2 = hexToBytes(bigintToFixed(shared.y))
    const mask = kdf(concatBytes(x2, y2), message.length)
    if (message.length !== 0 && mask.every((byte) => byte === 0)) continue
    const c2 = xorBytes(message, mask)
    const c3 = sm3Digest(concatBytes(x2, message, y2))
    return {c1: sm2C1(c1Point), c2, c3}
  }
}

export function sm2Encrypt(
  message: Uint8Array,
  publicKey: PublicKey,
  cipherMode: SM2Mode = C1C3C2,
  options: Sm2CipherOptions = {}
): Uint8Array {
  if (cipherMode !== C1C2C3 && cipherMode !== C1C3C2)
    throw new Error("Invalid cipher mode")
  const result = sm2EncryptBytes(copyBytes(message, "message"), publicKey)
  if (options.asn1)
    return encodeEncryption(result.c1, result.c2, result.c3, cipherMode)
  return cipherMode === C1C2C3
    ? concatBytes(result.c1, result.c2, result.c3)
    : concatBytes(result.c1, result.c3, result.c2)
}

function parseSm2Cipher(
  ciphertext: Uint8Array,
  cipherMode: SM2Mode,
  asn1: boolean
): {
  c1: AffinePoint
  c2: Uint8Array
  c3: Uint8Array
} {
  if (asn1) {
    const decoded = decodeEncryption(ciphertext)
    const c1 = decodePublicKey(encodePublicKey({x: decoded.x, y: decoded.y}))
    if (cipherMode === C1C2C3)
      return {c1, c2: decoded.hash, c3: decoded.cipher}
    return {c1, c2: decoded.cipher, c3: decoded.hash}
  }
  if (ciphertext.length < 96) throw new Error("Invalid ciphertext")
  const c1 = decodePublicKey(
    concatBytes(Uint8Array.of(0x04), ciphertext.subarray(0, 64))
  )
  const body = ciphertext.slice(64)
  if (body.length < 32) throw new Error("Invalid ciphertext")
  if (cipherMode === C1C2C3)
    return {c1, c2: body.slice(0, -32), c3: body.slice(-32)}
  return {c1, c2: body.slice(32), c3: body.slice(0, 32)}
}

export function sm2Decrypt(
  ciphertext: Uint8Array,
  privateKey: Uint8Array,
  cipherMode: SM2Mode = C1C3C2,
  options: Sm2CipherOptions = {}
): Uint8Array {
  if (cipherMode !== C1C2C3 && cipherMode !== C1C3C2)
    throw new Error("Invalid cipher mode")
  const input = copyBytes(ciphertext, "ciphertext")
  const secret = copyBytes(privateKey, "privateKey")
  try {
    const parsed = parseSm2Cipher(input, cipherMode, options.asn1 === true)
    if (parsed.c3.length !== 32) throw new Error("Invalid ciphertext hash")
    const shared = pointToAffine(
      scalarMultiply(affineToJacobian(parsed.c1), parsePrivateKey(secret))
    )
    const x2 = hexToBytes(bigintToFixed(shared.x))
    const y2 = hexToBytes(bigintToFixed(shared.y))
    const message = xorBytes(
      parsed.c2,
      kdf(concatBytes(x2, y2), parsed.c2.length)
    )
    const check = sm3Digest(concatBytes(x2, message, y2))
    return equalBytes(check, parsed.c3) ? message : new Uint8Array(0)
  } catch {
    return new Uint8Array(0)
  }
}

// Strict DER helpers are shared by SM2 signatures and ASN.1 ciphertext.
function derLength(length: number): Uint8Array {
  if (length < 128) return Uint8Array.of(length)
  const bytes: number[] = []
  for (let value = length; value > 0; value >>>= 8) bytes.unshift(value & 0xff)
  return Uint8Array.from([0x80 | bytes.length, ...bytes])
}

function derTlv(tag: number, value: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(tag), derLength(value.length), value)
}

function derInteger(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("Negative DER integer")
  let hex = value.toString(16)
  if (hex.length & 1) hex = `0${hex}`
  let bytes = hexToBytes(hex)
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.slice(1)
  if (bytes[0] & 0x80) bytes = concatBytes(Uint8Array.of(0), bytes)
  return derTlv(0x02, bytes)
}

function encodeDerValues(r: bigint, s: bigint): Uint8Array {
  return derTlv(0x30, concatBytes(derInteger(r), derInteger(s)))
}

type DerPart = { tag: number; value: Uint8Array; next: number }

function readDer(input: Uint8Array, offset: number): DerPart {
  if (offset + 2 > input.length) throw new Error("Invalid DER")
  const tag = input[offset]
  const firstLength = input[offset + 1]
  let length: number
  let header = 2
  if (firstLength < 0x80) length = firstLength
  else {
    const count = firstLength & 0x7f
    if (count === 0 || count > 4 || offset + 2 + count > input.length)
      throw new Error("Invalid DER")
    if (input[offset + 2] === 0) throw new Error("Non-minimal DER length")
    length = 0
    for (let i = 0; i < count; i++)
      length = length * 256 + input[offset + 2 + i]
    if (length < 128) throw new Error("Non-minimal DER length")
    header += count
  }
  const start = offset + header
  const next = start + length
  if (next > input.length) throw new Error("Invalid DER")
  return {tag, value: input.slice(start, next), next}
}

function decodeDerInteger(part: DerPart): bigint {
  if (
    part.tag !== 0x02 ||
    part.value.length === 0 ||
    (part.value[0] & 0x80) !== 0
  )
    throw new Error("Invalid DER integer")
  if (
    part.value.length > 1 &&
    part.value[0] === 0 &&
    (part.value[1] & 0x80) === 0
  )
    throw new Error("Non-minimal DER integer")
  return bytesToBigInt(part.value)
}

function decodeDerValues(input: Uint8Array): { r: bigint; s: bigint } {
  const bytes = copyBytes(input, "signature")
  const sequence = readDer(bytes, 0)
  if (sequence.tag !== 0x30 || sequence.next !== bytes.length)
    throw new Error("Invalid DER signature")
  const first = readDer(sequence.value, 0)
  const second = readDer(sequence.value, first.next)
  if (second.next !== sequence.value.length)
    throw new Error("Invalid DER signature")
  return {r: decodeDerInteger(first), s: decodeDerInteger(second)}
}

export function encodeDer(signature: Uint8Array): Uint8Array {
  const raw = copyBytes(signature, "signature")
  if (raw.length !== 64) throw new Error("Raw signature must be 64 bytes")
  return encodeDerValues(
    bytesToBigInt(raw.subarray(0, 32)),
    bytesToBigInt(raw.subarray(32))
  )
}

export function decodeDer(input: Uint8Array): Uint8Array {
  const {r, s} = decodeDerValues(input)
  if (r >= N || s >= N) throw new Error("Invalid DER signature")
  return concatBytes(bigintToBytes(r), bigintToBytes(s))
}

function encodeEncryption(
  c1: Uint8Array,
  c2: Uint8Array,
  c3: Uint8Array,
  cipherMode: SM2Mode
): Uint8Array {
  const x = derInteger(bytesToBigInt(c1.slice(0, 32)))
  const y = derInteger(bytesToBigInt(c1.slice(32)))
  const first = cipherMode === C1C2C3 ? c2 : c3
  const second = cipherMode === C1C2C3 ? c3 : c2
  return derTlv(
    0x30,
    concatBytes(x, y, derTlv(0x04, first), derTlv(0x04, second))
  )
}

function decodeEncryption(input: Uint8Array): {
  x: bigint
  y: bigint
  hash: Uint8Array
  cipher: Uint8Array
} {
  const bytes = copyBytes(input, "ciphertext")
  const sequence = readDer(bytes, 0)
  if (sequence.tag !== 0x30 || sequence.next !== bytes.length)
    throw new Error("Invalid ASN.1 ciphertext")
  const x = readDer(sequence.value, 0)
  const y = readDer(sequence.value, x.next)
  const hash = readDer(sequence.value, y.next)
  const cipher = readDer(sequence.value, hash.next)
  if (
    cipher.next !== sequence.value.length ||
    hash.tag !== 0x04 ||
    cipher.tag !== 0x04
  )
    throw new Error("Invalid ASN.1 ciphertext")
  return {
    x: decodeDerInteger(x),
    y: decodeDerInteger(y),
    hash: hash.value,
    cipher: cipher.value,
  }
}

export function sm2Sign(
  message: Uint8Array,
  privateKey: Uint8Array,
  options: {
    pointPool?: SignaturePoint[]
    der?: boolean
    hash?: boolean
    publicKey?: Uint8Array
    userId?: Uint8Array
  } = {}
): Uint8Array {
  const d = parsePrivateKey(privateKey)
  if (d === N - 1n) throw new Error("Invalid signing private key")
  const hash = options.hash !== false
  const publicKey = options.publicKey || getPublicKeyFromPrivateKey(privateKey)
  const data = copyBytes(message, "message")
  const e = hash
    ? bytesToBigInt(getHash(data, publicKey, options.userId))
    : bytesToBigInt(data)
  const inverseOnePlusD = inverse(1n + d, N)
  while (true) {
    const point = options.pointPool?.length
      ? options.pointPool.pop()!
      : getPoint()
    const k = bytesToBigInt(copyBytes(point.k, "point.k"))
    const x1 = bytesToBigInt(copyBytes(point.x1, "point.x1"))
    if (
      point.k.length !== 32 ||
      point.x1.length !== 32 ||
      k <= 0n ||
      k >= N ||
      x1 >= P
    )
      throw new Error("Invalid signing point")
    const r = modN(e + x1)
    if (r === 0n || r + k === N) continue
    const s = modN(inverseOnePlusD * (k - r * d))
    if (s === 0n) continue
    const raw = concatBytes(bigintToBytes(r), bigintToBytes(s))
    return options.der ? encodeDerValues(r, s) : raw
  }
}

/** @deprecated Use sm2Sign */
export const doSignature = sm2Sign

export function sm2Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: PublicKey,
  options: {
    der?: boolean
    hash?: boolean
    userId?: Uint8Array
  } = {}
): boolean {
  try {
    const point = resolvePublicKey(publicKey)
    const keyBytes = publicKeyBytes(publicKey)
    const data = copyBytes(message, "message")
    const e =
      options.hash === false
        ? bytesToBigInt(data)
        : bytesToBigInt(getHash(data, keyBytes, options.userId))
    let r: bigint
    let s: bigint
    if (options.der) ({r, s} = decodeDerValues(signature))
    else {
      const raw = copyBytes(signature, "signature")
      if (raw.length !== 64) return false
      r = bytesToBigInt(raw.subarray(0, 32))
      s = bytesToBigInt(raw.subarray(32))
    }
    if (r < 1n || r >= N || s < 1n || s >= N) return false
    const t = modN(r + s)
    if (t === 0n) return false
    const result = pointAdd(scalarMultiplyBase(s), multiplyPublicKey(point, t))
    const x = pointToAffine(result).x
    return modN(e + x) === r
  } catch {
    return false
  }
}

/** @deprecated Use sm2Verify */
export const doVerifySignature = sm2Verify
