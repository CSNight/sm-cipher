/*
 * SM3 hash function implementation.
 */

import {concatBytes, copyBytes, readU32BE, rotl32, writeU32BE, writeU64BE} from './utils.ts'

const SM3_IV = new Uint32Array([
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
])

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

export function sm3Digest(input: Uint8Array): Uint8Array {
    const bitLength = BigInt(input.length) * 8n
    const blockLength = Math.ceil((input.length + 9) / 64) * 64
    const padded = new Uint8Array(blockLength)
    padded.set(input)
    padded[input.length] = 0x80
    writeU64BE(padded, blockLength - 8, bitLength)

    const state = new Uint32Array(SM3_IV)
    const w = new Uint32Array(68)
    const w1 = new Uint32Array(64)
    for (let offset = 0; offset < padded.length; offset += 64) {
        for (let i = 0; i < 16; i++) w[i] = readU32BE(padded, offset + i * 4)
        for (let j = 16; j < 68; j++) {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)) ^ rotl32(w[j - 13], 7) ^ w[j - 6]
        }
        for (let j = 0; j < 64; j++) w1[j] = w[j] ^ w[j + 4]

        let a = state[0];
        let b = state[1];
        let c = state[2];
        let d = state[3]
        let e = state[4];
        let f = state[5];
        let g = state[6];
        let h = state[7]
        for (let j = 0; j < 64; j++) {
            const tj = j < 16 ? 0x79cc4519 : 0x7a879d8a
            const ss1 = rotl32((rotl32(a, 12) + e + rotl32(tj, j)) >>> 0, 7)
            const ss2 = ss1 ^ rotl32(a, 12)
            const tt1 = ((j < 16 ? ff0(a, b, c) : ff1(a, b, c)) + d + ss2 + w1[j]) >>> 0
            const tt2 = ((j < 16 ? gg0(e, f, g) : gg1(e, f, g)) + h + ss1 + w[j]) >>> 0
            d = c;
            c = rotl32(b, 9);
            b = a;
            a = tt1
            h = g;
            g = rotl32(f, 19);
            f = e;
            e = p0(tt2)
        }
        state[0] ^= a;
        state[1] ^= b;
        state[2] ^= c;
        state[3] ^= d
        state[4] ^= e;
        state[5] ^= f;
        state[6] ^= g;
        state[7] ^= h
    }
    const out = new Uint8Array(32)
    for (let i = 0; i < 8; i++) writeU32BE(out, i * 4, state[i])
    return out
}

export function sm3Hmac(keyInput: Uint8Array, messageInput: Uint8Array): Uint8Array {
    let key = copyBytes(keyInput, 'key')
    const message = copyBytes(messageInput, 'message')
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

export function sm3(input: Uint8Array, options?: { key: Uint8Array, mode?: 'hmac' }): Uint8Array {
    if (options && options.mode !== undefined && options.mode !== 'hmac') throw new Error('invalid mode')
    const data = copyBytes(input)
    return options ? sm3Hmac(options.key, data) : sm3Digest(data)
}


export function kdf(z: Uint8Array, length: number): Uint8Array {
    if (Math.ceil(length / 32) > 0xffffffff) throw new Error('KDF output is too long')
    const out = new Uint8Array(length)
    let offset = 0
    for (let counter = 1; offset < length; counter++) {
        const ct = new Uint8Array(4)
        ct[0] = counter >>> 24;
        ct[1] = counter >>> 16;
        ct[2] = counter >>> 8;
        ct[3] = counter
        const block = sm3Digest(concatBytes(z, ct))
        const take = Math.min(block.length, length - offset)
        out.set(block.subarray(0, take), offset)
        offset += take
    }
    return out
}
