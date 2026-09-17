/*
 * SM2/SM3/SM4 cryptography library - re-export entry point.
 * All algorithms are implemented in sm2.ts, sm3.ts, sm4.ts.
 * Utilities are in utils.ts. Types are in types.ts.
 */

export {
  setRandomSource,
  randomBytes,
  copyBytes,
  utf8ToBytes,
  bytesToUtf8,
  hexToBytes,
  bytesToHex,
  concatBytes,
  xorBytes,
  equalBytes,
} from "./utils.ts"

export {sm3, sm3Hmac, kdf} from "./sm3.ts"

export {
  C1C2C3,
  C1C3C2,
  SM2CipherMode,
  encodeDer,
  decodeDer,
  generateKeyPair,
  compressPublicKey,
  comparePublicKey,
  verifyPublicKey,
  getPublicKeyFromPrivateKey,
  precomputePublicKey,
  getPoint,
  getHash,
  sm2Encrypt,
  sm2Decrypt,
  sm2Sign,
  sm2Verify,
} from "./sm2.ts"

export {sm4Encrypt, sm4Decrypt, sm4Ghash} from "./sm4.ts"

export type {
  Bytes,
  SM2Mode,
  RandomSource,
  PrecomputedPublicKey,
  PublicKey,
  SignaturePoint,
  Sm2CipherOptions,
  SM4Options,
  GCMResult,
} from "./types.ts"
