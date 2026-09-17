/* Shared TypeScript types for sm-cipher. */
export type Bytes = Uint8Array
export type SM2Mode = 0 | 1
export type RandomSource = (length: number) => Uint8Array
export type PrecomputedPublicKey = Readonly<{ publicKey: Uint8Array, windowSize: number }>
export type PublicKey = Uint8Array | PrecomputedPublicKey
export type SignaturePoint = { k: Uint8Array, x1: Uint8Array, privateKey: Uint8Array, publicKey: Uint8Array }
export type Sm2CipherOptions = { asn1?: boolean }
export type SM4Options = {
    padding?: 'pkcs#7' | 'pkcs#5' | 'none' | null,
    mode?: 'cbc' | 'ecb' | 'gcm',
    iv?: Uint8Array,
    associatedData?: Uint8Array,
    tag?: Uint8Array
}
export type GCMResult = { output: Uint8Array, tag: Uint8Array }
