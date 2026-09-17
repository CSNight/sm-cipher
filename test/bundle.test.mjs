import assert from 'node:assert/strict'
import {test} from 'node:test'
import {
    bytesToHex,
    bytesToUtf8,
    C1C2C3,
    C1C3C2,
    generateKeyPair,
    hexToBytes,
    SM2CipherMode,
    sm2Decrypt,
    sm2Encrypt,
    sm3,
    sm4Encrypt,
    utf8ToBytes,
} from 'sm-cipher'

test('Vite ESM bundle exposes the byte API and executes all algorithms', () => {
    assert.deepEqual(SM2CipherMode, {C1C2C3, C1C3C2})
    const pair = generateKeyPair()
    const message = utf8ToBytes('bundle-中文')
    const cipher = sm2Encrypt(message, pair.publicKey, C1C3C2)
    assert.equal(bytesToUtf8(sm2Decrypt(cipher, pair.privateKey, C1C3C2)), 'bundle-中文')
    assert.equal(bytesToHex(sm3(utf8ToBytes('abc'))), '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
    const key = hexToBytes('0123456789abcdeffedcba9876543210')
    const block = sm4Encrypt(key, key, {padding: 'none'})
    assert.equal(bytesToHex(block), '681edf34d206965e86b3e94f536e4246')
})
