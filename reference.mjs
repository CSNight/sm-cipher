import {createRequire} from 'node:module'
import {resolve} from 'node:path'

const require = createRequire(import.meta.url)
export const original = process.env.ORIGINAL_SM_CRYPTO
    ? require(resolve(process.env.ORIGINAL_SM_CRYPTO))
    : require('sm-crypto')
export const referenceName = process.env.ORIGINAL_SM_CRYPTO || 'sm-crypto@0.5.7'
export const optimized = require('sm-crypto-v2')
export const optimizedName = 'sm-crypto-v2@1.15.1'
export const optimizedShortName = 'sm-crypto-2'
