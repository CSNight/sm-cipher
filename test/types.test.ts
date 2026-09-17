import {
  bytesToHex,
  bytesToUtf8,
  C1C2C3,
  C1C3C2,
  GCMResult,
  generateKeyPair,
  hexToBytes,
  PrecomputedPublicKey,
  precomputePublicKey,
  PublicKey,
  SignaturePoint,
  SM2CipherMode,
  Sm2CipherOptions,
  sm2Decrypt,
  sm2Encrypt,
  sm2Sign,
  sm2Verify,
  sm3,
  sm4Decrypt,
  sm4Encrypt,
  SM4Options,
  utf8ToBytes,
} from "../src/smcrypto.ts"

const pair = generateKeyPair()
const prepared: PrecomputedPublicKey = precomputePublicKey(pair.publicKey, 4)
const message: Uint8Array = utf8ToBytes("abc")
const cipher: Uint8Array = sm2Encrypt(message, prepared, SM2CipherMode.C1C3C2)
const plain: Uint8Array = sm2Decrypt(cipher, pair.privateKey, C1C3C2)
const hash: Uint8Array = sm3(plain)
const signature: Uint8Array = sm2Sign(plain, pair.privateKey, { der: true })
const valid: boolean = sm2Verify(plain, signature, prepared, { der: true })
const key = hexToBytes("0123456789abcdeffedcba9876543210")
const ecb: Uint8Array = sm4Encrypt(plain, key)
const result: GCMResult = sm4Encrypt(plain, key, { mode: "gcm" }) as GCMResult
const recovered: Uint8Array = sm4Decrypt(result.output, key, {
  mode: "gcm",
  tag: result.tag,
})
const text: string = bytesToUtf8(recovered)
const encoded: string = bytesToHex(hash)

// Type-check PublicKey union
const _pk1: PublicKey = pair.publicKey
const _pk2: PublicKey = prepared

// Type-check options
const _opts: Sm2CipherOptions = { asn1: true }
const _sm4opts: SM4Options = { padding: "pkcs#7", mode: "cbc" }

// Type-check SignaturePoint (from sm2Sign internals — just verify import)
type _CheckSignaturePoint = SignaturePoint

void [C1C2C3, C1C3C2, valid, ecb, text, encoded, _pk1, _pk2, _opts, _sm4opts]
