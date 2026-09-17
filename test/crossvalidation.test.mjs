/*
 * Cross-library validation suite.
 *
 * Baseline oracle: sm-crypto (the de-facto reference implementation of the
 * Chinese national cryptography standards in JS). Every algorithm result
 * produced by this library (sm-cipher) is checked bidirectionally against
 * sm-crypto, and sm-crypto-v2 is triangulated against both to confirm all
 * three implementations agree on the same inputs.
 *
 * This file intentionally does NOT test this library's own error handling,
 * input validation, or edge-case behavior in isolation (see test.mjs for
 * that) - it exists purely to prove algorithmic consistency across
 * implementations.
 */
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {randomBytes} from 'node:crypto'
import {
    bytesToHex,
    compressPublicKey,
    generateKeyPair,
    getPublicKeyFromPrivateKey,
    hexToBytes,
    sm2Decrypt,
    sm2Encrypt,
    sm2Sign,
    sm2Verify,
    sm3,
    sm4Decrypt,
    sm4Encrypt,
    utf8ToBytes,
    verifyPublicKey,
} from '../src/index.ts'
import {optimized, optimizedName, original, referenceName} from './reference.mjs'

const privateHex = '75b25a5d6101013e9be25816f81cf1f64bf78ea8383b32d61f5b26e6f1429e70'
const publicHex = original.sm2.getPublicKeyFromPrivateKey(privateHex)
const keyHex = '0123456789abcdeffedcba9876543210'
const ivHex = '000102030405060708090a0b0c0d0e0f'
const messageText = 'hello world! 我是 juneandgreen. 😀'
const privateKey = hexToBytes(privateHex)
const publicKey = hexToBytes(publicHex)
const key = hexToBytes(keyHex)
const iv = hexToBytes(ivHex)
const message = utf8ToBytes(messageText)
const EMPTY = new Uint8Array(0)
const equal = (a, b) => assert.deepEqual(Array.from(a), Array.from(b))
const unaligned = bytes => {
    const buffer = new Uint8Array(bytes.length + 5)
    buffer.fill(0xa5)
    buffer.set(bytes, 1)
    return buffer.subarray(1, 1 + bytes.length)
}

console.log(`[crossvalidation] baseline oracle (sm-crypto): ${referenceName}`)
console.log(`[crossvalidation] triangulated library: ${optimizedName}`)

// ---------------------------------------------------------------------------
// SM3 vs sm-crypto (baseline)
// ---------------------------------------------------------------------------

test('SM3: sm-cipher matches sm-crypto baseline over random and text inputs', () => {
    for (const length of [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 4096]) {
        const data = new Uint8Array(randomBytes(length))
        assert.equal(bytesToHex(sm3(data)), original.sm3(Array.from(data)))
    }
    for (const text of ['', messageText, '﻿abc', '你好', 'a'.repeat(1000)]) {
        assert.equal(bytesToHex(sm3(utf8ToBytes(text))), original.sm3(text))
    }
})

// ---------------------------------------------------------------------------
// SM3 vs sm-crypto-v2 (triangulation)
// ---------------------------------------------------------------------------

test('SM3: sm-cipher matches sm-crypto-v2, and sm-crypto-v2 matches the sm-crypto baseline', () => {
    for (const length of [0, 1, 32, 64, 65, 1024]) {
        const data = new Uint8Array(randomBytes(length))
        const baseline = original.sm3(Array.from(data))
        const v2 = optimized.sm3(data)
        assert.equal(bytesToHex(sm3(data)), v2)
        assert.equal(v2, baseline)
    }
})

// ---------------------------------------------------------------------------
// SM2 key generation vs sm-crypto (baseline)
// ---------------------------------------------------------------------------

test('SM2 keys: sm-cipher public-key derivation matches sm-crypto baseline', () => {
    equal(getPublicKeyFromPrivateKey(privateKey), publicKey)
    assert.equal(bytesToHex(compressPublicKey(publicKey)), original.sm2.compressPublicKeyHex(publicHex))
    for (let i = 0; i < 5; i++) {
        const pair = generateKeyPair()
        assert.equal(original.sm2.verifyPublicKey(bytesToHex(pair.publicKey)), true)
        assert.equal(original.sm2.getPublicKeyFromPrivateKey(bytesToHex(pair.privateKey)), bytesToHex(pair.publicKey))
        assert.equal(verifyPublicKey(hexToBytes(original.sm2.getPublicKeyFromPrivateKey(bytesToHex(pair.privateKey)))), true)
    }
})

test('SM2 keys: sm-crypto-v2 derivation agrees with sm-cipher and the sm-crypto baseline', () => {
    for (let i = 0; i < 5; i++) {
        const v2Pair = optimized.sm2.generateKeyPairHex()
        equal(getPublicKeyFromPrivateKey(hexToBytes(v2Pair.privateKey)), hexToBytes(v2Pair.publicKey))
        assert.equal(original.sm2.getPublicKeyFromPrivateKey(v2Pair.privateKey), v2Pair.publicKey)
    }
})

// ---------------------------------------------------------------------------
// SM2 encrypt/decrypt: bidirectional against sm-crypto (baseline)
// ---------------------------------------------------------------------------

for (const mode of [0, 1]) {
    test(`SM2 encrypt/decrypt (mode ${mode}): sm-cipher <-> sm-crypto baseline`, () => {
        for (const input of [EMPTY, message, Uint8Array.of(0, 128, 255, 1), unaligned(randomBytes(65))]) {
            const oldCipher = hexToBytes(original.sm2.doEncrypt(Array.from(input), publicHex, mode))
            equal(sm2Decrypt(oldCipher, privateKey, mode), input)

            const newCipher = sm2Encrypt(input, publicKey, mode)
            equal(original.sm2.doDecrypt(bytesToHex(newCipher), privateHex, mode, {output: 'array'}), input)
        }
    })
}

// ---------------------------------------------------------------------------
// SM2 encrypt/decrypt: triangulation with sm-crypto-v2
// ---------------------------------------------------------------------------

test('SM2 encrypt/decrypt: sm-cipher <-> sm-crypto-v2, cross-checked against sm-crypto baseline', () => {
    const cipherFromCipher = sm2Encrypt(message, publicKey)
    equal(optimized.sm2.doDecrypt(bytesToHex(cipherFromCipher), privateHex, 1, {output: 'array'}), message)
    equal(sm2Decrypt(hexToBytes(optimized.sm2.doEncrypt(message, publicHex, 1)), privateKey), message)

    // Triangulate: sm-crypto-v2's own ciphertext must also decrypt correctly under sm-crypto baseline.
    const v2Cipher = optimized.sm2.doEncrypt(message, publicHex, 1)
    equal(original.sm2.doDecrypt(v2Cipher, privateHex, 1, {output: 'array'}), message)
})

// ---------------------------------------------------------------------------
// SM2 sign/verify: bidirectional against sm-crypto (baseline)
// ---------------------------------------------------------------------------

for (const der of [false, true]) {
    for (const hash of [false, true]) {
        test(`SM2 sign/verify (der=${der}, hash=${hash}): sm-cipher <-> sm-crypto baseline`, () => {
            for (const input of [message, unaligned(Uint8Array.of(0, 128, 255, 1, 3))]) {
                const options = {der, hash}
                const oldSignature = hexToBytes(original.sm2.doSignature(Array.from(input), privateHex, options))
                assert.equal(sm2Verify(input, oldSignature, publicKey, options), true)

                const newSignature = sm2Sign(input, privateKey, options)
                assert.equal(original.sm2.doVerifySignature(Array.from(input), bytesToHex(newSignature), publicHex, options), true)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// SM2 sign/verify: triangulation with sm-crypto-v2
// ---------------------------------------------------------------------------

test('SM2 sign/verify: sm-cipher <-> sm-crypto-v2, cross-checked against sm-crypto baseline', () => {
    const signature = sm2Sign(message, privateKey)
    assert.equal(optimized.sm2.doVerifySignature(message, bytesToHex(signature), publicHex, {hash: true}), true)
    assert.equal(original.sm2.doVerifySignature(Array.from(message), bytesToHex(signature), publicHex, {hash: true}), true)

    const v2Signature = optimized.sm2.doSignature(message, privateHex, {hash: true})
    assert.equal(sm2Verify(message, hexToBytes(v2Signature), publicKey), true)
    assert.equal(original.sm2.doVerifySignature(Array.from(message), v2Signature, publicHex, {hash: true}), true)
})

// ---------------------------------------------------------------------------
// SM4 ECB/CBC: bidirectional against sm-crypto (baseline)
// ---------------------------------------------------------------------------

for (const mode of ['ecb', 'cbc']) {
    for (const padding of ['pkcs#5', 'pkcs#7', 'none']) {
        test(`SM4 ${mode}/${padding}: sm-cipher <-> sm-crypto baseline exact ciphertext`, () => {
            const lengths = padding === 'none' ? [0, 16, 32, 256] : [0, 1, 15, 16, 17, 31, 32, 65, 256]
            for (const length of lengths) {
                const input = new Uint8Array(randomBytes(length))
                const newOptions = {mode, padding, iv}
                const oldOptions = {mode, padding, iv: ivHex, output: 'array'}
                const newCipher = sm4Encrypt(input, key, newOptions)
                const oldCipher = original.sm4.encrypt(Array.from(input), keyHex, oldOptions)
                equal(newCipher, oldCipher)
                equal(sm4Decrypt(new Uint8Array(oldCipher), key, newOptions), input)
                equal(original.sm4.decrypt(Array.from(newCipher), keyHex, oldOptions), input)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// SM4 ECB/CBC: triangulation with sm-crypto-v2
// ---------------------------------------------------------------------------

for (const mode of ['ecb', 'cbc']) {
    test(`SM4 ${mode}: sm-cipher <-> sm-crypto-v2, cross-checked against sm-crypto baseline`, () => {
        const options = mode === 'cbc' ? {mode, iv} : {mode}
        const v2Options = mode === 'cbc' ? {mode, iv: ivHex, output: 'array'} : {mode, output: 'array'}
        const oldOptions = mode === 'cbc' ? {mode, iv: ivHex, output: 'array'} : {mode, output: 'array'}
        const encrypted = sm4Encrypt(message, key, options)
        equal(optimized.sm4.encrypt(message, keyHex, v2Options), encrypted)
        equal(optimized.sm4.decrypt(encrypted, keyHex, v2Options), message)
        equal(sm4Decrypt(encrypted, key, options), message)
        // Triangulate: sm-crypto-v2's ciphertext also matches the sm-crypto baseline exactly.
        equal(original.sm4.encrypt(Array.from(message), keyHex, oldOptions), encrypted)
    })
}

// ---------------------------------------------------------------------------
// SM4-GCM: triangulation with sm-crypto-v2 (sm-crypto 0.5.7 has no GCM support)
// ---------------------------------------------------------------------------

const gcmIv = hexToBytes('00001234567800000000abcd')

test('SM4-GCM: sm-cipher <-> sm-crypto-v2 bidirectional (sm-crypto has no GCM mode)', () => {
    for (const length of [0, 1, 15, 16, 17, 65, 256]) {
        const plain = unaligned(randomBytes(length))
        const aadBytes = unaligned(randomBytes(23))
        const newResult = sm4Encrypt(plain, key, {mode: 'gcm', iv: gcmIv, associatedData: aadBytes})
        const oldPlain = optimized.sm4.decrypt(bytesToHex(newResult.output), keyHex, {
            mode: 'gcm',
            iv: bytesToHex(gcmIv),
            associatedData: bytesToHex(aadBytes),
            tag: bytesToHex(newResult.tag),
            output: 'array',
        })
        equal(oldPlain, plain)

        const oldResult = optimized.sm4.encrypt(plain, keyHex, {
            mode: 'gcm', iv: bytesToHex(gcmIv), associatedData: bytesToHex(aadBytes), output: 'array', outputTag: true,
        })
        equal(sm4Decrypt(oldResult.output, key, {
            mode: 'gcm', iv: gcmIv, associatedData: aadBytes, tag: oldResult.tag,
        }), plain)
        equal(newResult.output, oldResult.output)
        equal(newResult.tag, oldResult.tag)
    }
})
