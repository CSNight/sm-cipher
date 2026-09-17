import {performance} from 'node:perf_hooks'
import {cpus} from 'node:os'
import {
    bytesToHex,
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
} from './src/smcrypto.ts'
import {optimized, optimizedName, optimizedShortName, original, referenceName} from './reference.mjs'

const privateHex = '75b25a5d6101013e9be25816f81cf1f64bf78ea8383b32d61f5b26e6f1429e70'
const privateKey = hexToBytes(privateHex)
const publicKey = getPublicKeyFromPrivateKey(privateKey)
const publicHex = bytesToHex(publicKey)
const keyHex = '0123456789abcdeffedcba9876543210'
const ivHex = '000102030405060708090a0b0c0d0e0f'
const key = hexToBytes(keyHex)
const iv = hexToBytes(ivHex)
const data = Uint8Array.from({length: 4096}, (_, i) => i & 255)
const oldData = Array.from(data)
const message = utf8ToBytes('SM2 interoperability benchmark: ' + 'abc'.repeat(32))
const oldMessage = Array.from(message)
const cipher = sm2Encrypt(message, publicKey)
const signature = sm2Sign(message, privateKey)
const cipherHex = bytesToHex(cipher)
const signatureHex = bytesToHex(signature)
const scale = Number(process.env.BENCH_SCALE || 1)
if (!Number.isFinite(scale) || scale <= 0) throw new Error('Invalid BENCH_SCALE')
const samples = Number(process.env.BENCH_SAMPLES || 5)
if (!Number.isInteger(samples) || samples < 3) throw new Error('BENCH_SAMPLES must be an integer >= 3')
let sink

function measure(fn, iterations) {
    const timings = []
    for (let i = 0; i < Math.min(iterations, 20); i++) sink = fn()
    for (let sample = 0; sample < samples; sample++) {
        const start = performance.now()
        for (let i = 0; i < iterations; i++) sink = fn()
        timings.push(performance.now() - start)
    }
    timings.sort((a, b) => a - b)
    return {ms: timings[Math.floor(timings.length / 2)], min: timings[0], max: timings.at(-1)}
}

const ecbCipher = sm4Encrypt(data, key)
const cbcCipher = sm4Encrypt(data, key, {mode: 'cbc', iv})
const ecbCipherOld = Array.from(ecbCipher)
const cbcCipherOld = Array.from(cbcCipher)
const gcmCipher = sm4Encrypt(data, key, {mode: 'gcm', iv})
const gcmCipherHex = bytesToHex(gcmCipher.output)
const gcmTagHex = bytesToHex(gcmCipher.tag)

const cases = [
    ['SM2 generateKeyPair', 100, () => generateKeyPair(), () => original.sm2.generateKeyPairHex(), () => optimized.sm2.generateKeyPairHex()],
    ['SM2 encrypt', 80, () => sm2Encrypt(message, publicKey), () => original.sm2.doEncrypt(oldMessage, publicHex), () => optimized.sm2.doEncrypt(oldMessage, publicHex)],
    ['SM2 decrypt', 100, () => sm2Decrypt(cipher, privateKey), () => original.sm2.doDecrypt(cipherHex, privateHex, 1, {output: 'array'}), () => optimized.sm2.doDecrypt(cipherHex, privateHex, 1, {output: 'array'})],
    ['SM2 sign', 100, () => sm2Sign(message, privateKey), () => original.sm2.doSignature(oldMessage, privateHex, {hash: true}), () => optimized.sm2.doSignature(message, privateHex, {hash: true})],
    ['SM2 verify', 80, () => sm2Verify(message, signature, publicKey), () => original.sm2.doVerifySignature(oldMessage, signatureHex, publicHex, {hash: true}), () => optimized.sm2.doVerifySignature(message, signatureHex, publicHex, {hash: true})],
    ['SM3 4KiB', 1000, () => sm3(data), () => original.sm3(oldData), () => optimized.sm3(data)],
    ['SM4 ECB encrypt 4KiB', 1000, () => sm4Encrypt(data, key), () => original.sm4.encrypt(oldData, keyHex, {output: 'array'}), () => optimized.sm4.encrypt(data, keyHex, {output: 'array'})],
    ['SM4 ECB decrypt 4KiB', 1000, () => sm4Decrypt(ecbCipher, key), () => original.sm4.decrypt(ecbCipherOld, keyHex, {output: 'array'}), () => optimized.sm4.decrypt(ecbCipher, keyHex, {output: 'array'})],
    ['SM4 CBC encrypt 4KiB', 1000, () => sm4Encrypt(data, key, {mode: 'cbc', iv}), () => original.sm4.encrypt(oldData, keyHex, {mode: 'cbc', iv: ivHex, output: 'array'}), () => optimized.sm4.encrypt(data, keyHex, {mode: 'cbc', iv: ivHex, output: 'array'})],
    ['SM4 CBC decrypt 4KiB', 1000, () => sm4Decrypt(cbcCipher, key, {mode: 'cbc', iv}), () => original.sm4.decrypt(cbcCipherOld, keyHex, {mode: 'cbc', iv: ivHex, output: 'array'}), () => optimized.sm4.decrypt(cbcCipher, keyHex, {mode: 'cbc', iv: ivHex, output: 'array'})],
    ['SM4 GCM encrypt 4KiB', 1000, () => sm4Encrypt(data, key, {mode: 'gcm', iv}), null, () => optimized.sm4.encrypt(data, keyHex, {mode: 'gcm', iv: ivHex, output: 'array', outputTag: true})],
    ['SM4 GCM decrypt 4KiB', 1000, () => sm4Decrypt(gcmCipher.output, key, {mode: 'gcm', iv, tag: gcmCipher.tag}), null, () => optimized.sm4.decrypt(gcmCipherHex, keyHex, {mode: 'gcm', iv: ivHex, tag: gcmTagHex, output: 'array'})],
]
console.log(`Node ${process.version}; ${process.platform}/${process.arch}; ${cpus()[0]?.model}`)
console.log(`Comparison: ${referenceName}, ${optimizedName} (${optimizedShortName}); ${samples} samples; median; BENCH_SCALE=${scale}`)
const rows = []
for (const [name, count, fresh, reference, v2] of cases) {
    const iterations = Math.max(1, Math.round(count * scale))
    const n = measure(fresh, iterations);
    const o = reference ? measure(reference, iterations) : null
    const v = measure(v2, iterations)
    rows.push({
        case: name,
        iterations,
        'sm-cipher ops/s': Math.round(iterations * 1000 / n.ms),
        'sm-crypto ops/s': o ? Math.round(iterations * 1000 / o.ms) : '-',
        'sm-crypto-v2 ops/s': Math.round(iterations * 1000 / v.ms),
        'vs sm-crypto': o ? `${(o.ms / n.ms).toFixed(2)}x` : '-',
        'vs v2': `${(v.ms / n.ms).toFixed(2)}x`,
    })
}
console.table(rows)
void sink
