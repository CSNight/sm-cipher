# sm-cipher

Dependency-free, byte-oriented SM2 / SM3 / SM4 implementation for TypeScript
ESM. Every algorithm input and output is a `Uint8Array`; string and
hexadecimal conversion is explicit at the application boundary.

The implementation provides native `bigint` SM2, typed-array SM3/HMAC-SM3,
SM4 ECB/CBC/GCM, strict DER parsing, SM2 ASN.1 ciphertexts, public-key
precomputation, and a standalone GHASH window core. It has no runtime
dependencies.

## Install

```bash
npm install sm-cipher
```

## Quickstart

```ts
import {
  C1C3C2,
  generateKeyPair,
  sm2Encrypt,
  sm2Decrypt,
  sm2Sign,
  sm2Verify,
  sm3,
  sm4Encrypt,
  sm4Decrypt,
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  utf8ToBytes,
} from 'sm-cipher'

const message = utf8ToBytes('message')
const pair = generateKeyPair()

// SM2 asymmetric encryption (C1C3C2 is the modern default)
const cipher = sm2Encrypt(message, pair.publicKey, C1C3C2)
const plaintext = sm2Decrypt(cipher, pair.privateKey, C1C3C2)

// SM2 signing
const signature = sm2Sign(message, pair.privateKey, { der: true })
const valid = sm2Verify(message, signature, pair.publicKey, { der: true })

// SM3 hashing
const digest = sm3(message)

// SM4 symmetric encryption (ECB by default)
const key = hexToBytes('0123456789abcdeffedcba9876543210')
const sm4Cipher = sm4Encrypt(message, key)
const sm4Plain = sm4Decrypt(sm4Cipher, key)

console.log(bytesToUtf8(plaintext), bytesToHex(digest), valid, bytesToUtf8(sm4Plain))
```

## API

### SM2

| Function | Signature | Notes |
| --- | --- | --- |
| `generateKeyPair(seed?)` | `(seed?: Uint8Array) => { privateKey, publicKey }` | Uses a secure random source unless a seed is supplied. |
| `getPublicKeyFromPrivateKey(privateKey)` | `(Uint8Array) => Uint8Array` | Derives the uncompressed public key. |
| `compressPublicKey(publicKey)` | `(Uint8Array) => Uint8Array` | Uncompressed to compressed point form. |
| `comparePublicKey(a, b)` | `(Uint8Array, Uint8Array) => boolean` | Compressed/uncompressed-safe equality. |
| `verifyPublicKey(publicKey)` | `(Uint8Array) => boolean` | Validates the point is on the curve. |
| `precomputePublicKey(publicKey, windowSize?)` | `(Uint8Array, number) => PrecomputedPublicKey` | Speeds up repeated encryption/verification with one key. |
| `sm2Encrypt(message, publicKey, mode?, options?)` | `(Uint8Array, PublicKey, SM2Mode, Sm2CipherOptions) => Uint8Array` | `mode` defaults to `C1C3C2`. `{ asn1: true }` for ASN.1 ciphertext. |
| `sm2Decrypt(cipher, privateKey, mode?, options?)` | `(Uint8Array, Uint8Array, SM2Mode, Sm2CipherOptions) => Uint8Array` | Mirrors `sm2Encrypt`. |
| `sm2Sign(message, privateKey, options?)` | `(Uint8Array, Uint8Array, options) => Uint8Array` | `{ der: true }`, `{ hash: true }`, `{ userId }`, `{ pointPool }`. |
| `sm2Verify(message, signature, publicKey, options?)` | `(Uint8Array, Uint8Array, PublicKey, options) => boolean` | Mirrors `sm2Sign` options. |
| `encodeDer(raw)` / `decodeDer(der)` | `(Uint8Array) => Uint8Array` | Strict SM2 signature DER codec. |
| `getPoint()` | `() => SignaturePoint` | Precomputes one `(k, x1)` signature nonce for a pool. |
| `C1C2C3`, `C1C3C2`, `SM2CipherMode` | constants | `C1C2C3 = 0`, `C1C3C2 = 1`. |

### SM3

| Function | Signature | Notes |
| --- | --- | --- |
| `sm3(input, options?)` | `(Uint8Array, { key, mode? }) => Uint8Array` | Plain digest, or HMAC-SM3 when `options.key` is given. |
| `sm3Hmac(key, message)` | `(Uint8Array, Uint8Array) => Uint8Array` | Direct HMAC-SM3. |
| `kdf(z, length)` | `(Uint8Array, number) => Uint8Array` | SM2 key derivation function. |

### SM4

| Function | Signature | Notes |
| --- | --- | --- |
| `sm4Encrypt(input, key, options?)` | `(Uint8Array, Uint8Array, SM4Options) => Uint8Array \| GCMResult` | `mode`: `'ecb'` (default), `'cbc'`, `'gcm'`. Returns `{ output, tag }` for GCM. |
| `sm4Decrypt(input, key, options?)` | `(Uint8Array, Uint8Array, SM4Options) => Uint8Array` | Pass `tag` in options for GCM. |
| `sm4Ghash(h, ...segments)` | `(Uint8Array, ...Uint8Array[]) => Uint8Array` | Standalone GHASH core; each segment is zero-padded to 16 bytes. |

SM4 `padding` is `'pkcs#7'` / `'pkcs#5'` / `'none'` (default `'pkcs#7'`), and
CBC/GCM require an `iv`.

### Byte / string helpers

| Function | Signature |
| --- | --- |
| `hexToBytes(string)` | `(string) => Uint8Array` |
| `bytesToHex(Uint8Array)` | `(Uint8Array) => string` |
| `utf8ToBytes(string)` | `(string) => Uint8Array` |
| `bytesToUtf8(Uint8Array)` | `(Uint8Array) => string` |
| `concatBytes(...Uint8Array[])` | `(...Uint8Array[]) => Uint8Array` |
| `xorBytes(a, b)` | `(Uint8Array, Uint8Array) => Uint8Array` |
| `equalBytes(a, b)` | `(Uint8Array, Uint8Array) => boolean` |
| `copyBytes(input, name?)` | `(Uint8Array, string) => Uint8Array` |
| `setRandomSource(source?)` | `(RandomSource?) => void` |
| `randomBytes(length)` | `(number) => Uint8Array` |

## Mini Program Runtimes

`Uint8Array` is a typed view over `ArrayBuffer` and is supported by current
mini-program runtimes. The implementation does not require `TextEncoder`,
`TextDecoder`, `Buffer`, Node APIs, or browser DOM APIs.

Native `BigInt` is required and cannot be lowered by Vite. The output target
is therefore ES2020. Test the minimum mini-program base library and device
engines used by the application before release.

Browsers and Node use `globalThis.crypto.getRandomValues` by default. WeChat
exposes secure randomness as the asynchronous `wx.getRandomValues` API
instead, so preload a secure pool and install a synchronous source before
generating SM2 keys, encryption nonces, or signatures:

```ts
import { setRandomSource } from 'sm-cipher'

let pool = new Uint8Array(0)
let offset = 0

export function refillRandomPool(length = 65536): Promise<void> {
  return new Promise((resolve, reject) => {
    wx.getRandomValues({
      length,
      success(result) {
        pool = new Uint8Array(result.randomValues)
        offset = 0
        resolve()
      },
      fail: reject,
    })
  })
}

await refillRandomPool()
setRandomSource(length => {
  if (offset + length > pool.length) throw new Error('Secure random pool exhausted')
  const output = pool.slice(offset, offset + length)
  pool.fill(0, offset, offset + length)
  offset += length
  return output
})
```

Do not replace the source with `Math.random()`.

## Performance

`npm run bench` compares this package with `sm-crypto@0.5.7` and
`sm-crypto-v2@1.15.1` (also called sm-crypto-2). The figures below are
operations per second, median of 5 samples on Node 25.2.1, Windows x64,
Intel Core i5-1135G7 @ 2.40GHz. SM2 signing and verification use
`hash: true` in all three libraries. SM4 uses 4 KiB buffers; inputs and
ciphertexts are prepared before timing. Higher is better; results depend
on hardware, runtime, and system load.

| Case | sm-cipher | sm-crypto | sm-crypto-v2 |
| --- | ---: | ---: | ---: |
| SM2 generateKeyPair | 534 | 95 | 2,174 |
| SM2 encrypt | 369 | 51 | 220 |
| SM2 decrypt | 598 | 104 | 269 |
| SM2 sign | 214 | 43 | 1,010 |
| SM2 verify | 323 | 50 | 238 |
| SM3 (4 KiB) | 23,451 | 14,561 | 30,488 |
| SM4 ECB encrypt (4 KiB) | 10,153 | 8,516 | 10,552 |
| SM4 ECB decrypt (4 KiB) | 11,056 | 10,055 | 13,964 |
| SM4 CBC encrypt (4 KiB) | 12,359 | 8,842 | 11,881 |
| SM4 CBC decrypt (4 KiB) | 11,356 | 9,367 | 12,012 |
| SM4 GCM encrypt (4 KiB) | 7,431 | N/A | 5,481 |
| SM4 GCM decrypt (4 KiB) | 7,518 | N/A | 2,894 |

`sm-crypto@0.5.7` does not provide GCM. This library is faster on most
listed operations than `sm-crypto`, while `sm-crypto-v2` is faster on
SM2 key generation/signing and several SM3/SM4 cases. Small differences
should be re-measured on the target device.

Run the benchmark yourself:

```bash
npm run bench
```

Environment variables `BENCH_SCALE` (iteration multiplier) and
`BENCH_SAMPLES` (sample count, default 5) tune the run.

## Vite Library Build

```bash
npm install
npm run build
npm run test:bundle
```

Vite library mode emits `dist/smcrypto.js` as an ES2020 ESM library.
TypeScript also emits `dist/*.d.ts`. The package `exports` field points
at the entry files. Building requires a Node.js version supported by
Vite 8 (Node 20.19+ or 22.12+); the built library targets ES2020.

## Persistent Verification

The test and benchmark files are intentionally retained for future changes.

```bash
npm test
npm run typecheck
npm run test:bundle
npm run bench
```

Run the one-million-iteration SM4 standard vector with:

```bash
SMCRYPTO_LONG_TESTS=1 npm test
```

`test.mjs` performs bidirectional SM2 encryption/decryption and signing
checks against pinned `sm-crypto@0.5.7`, checks SM2/SM3/SM4 ECB/CBC
against `sm-crypto-v2@1.15.1`, and performs bidirectional SM4-GCM checks.
It also uses Node/OpenSSL as an SM3/HMAC/SM4 oracle
and checks GHASH/GCM against an independent bit-serial implementation. Set
`ORIGINAL_SM_CRYPTO` to a local repository entry point to test a source
checkout.

## Security Boundary

The default random source is cryptographically secure, tags are compared
without early exit, and GCM authenticates ciphertext before decryption.
Native JavaScript `bigint` arithmetic is not guaranteed to be constant-time,
so this library is not a side-channel-hardened cryptographic module.

## License

MIT
