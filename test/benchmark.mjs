import { spawnSync } from "node:child_process"
import { cpus } from "node:os"
import { resolve } from "node:path"
import { performance } from "node:perf_hooks"
import { pathToFileURL } from "node:url"
import {
  bytesToHex,
  generateKeyPair,
  getPublicKeyFromPrivateKey,
  hexToBytes,
  precomputePublicKey,
  sm2Decrypt,
  sm2Encrypt,
  sm2Sign,
  sm2Verify,
  sm3,
  sm4Decrypt,
  sm4Encrypt,
  utf8ToBytes,
} from "../dist/smcrypto.js"
import {
  optimized,
  optimizedName,
  optimizedShortName,
  original,
  referenceName,
} from "../reference.mjs"

const sampleDurationMs = Number(process.env.BENCH_TIME_MS || 150)
const samples = Number(process.env.BENCH_SAMPLES || 5)
const coldSamples = Number(process.env.BENCH_COLD_SAMPLES || 5)
if (!Number.isFinite(sampleDurationMs) || sampleDurationMs < 50)
  throw new Error("BENCH_TIME_MS must be at least 50")
if (!Number.isInteger(samples) || samples < 3)
  throw new Error("BENCH_SAMPLES must be an integer >= 3")
if (!Number.isInteger(coldSamples) || coldSamples < 3)
  throw new Error("BENCH_COLD_SAMPLES must be an integer >= 3")

const startupOnly = process.argv.includes("--startup-only")
const throughputOnly = process.argv.includes("--throughput-only")
if (startupOnly && throughputOnly)
  throw new Error("Choose only one benchmark mode")

let sink

function runBatch(fn, iterations) {
  const start = performance.now()
  for (let i = 0; i < iterations; i++) sink = fn()
  return performance.now() - start
}

function calibratedIterations(fn, targetMs) {
  let iterations = 1
  let elapsed
  do {
    elapsed = runBatch(fn, iterations)
    if (elapsed < Math.min(25, targetMs / 3)) iterations *= 2
  } while (elapsed < Math.min(25, targetMs / 3))
  return Math.max(iterations, Math.ceil((iterations * targetMs) / elapsed))
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.floor(sorted.length / 2)]
}

function measureGroup(implementations, targetMs = sampleDurationMs) {
  const results = new Map()
  for (const implementation of implementations) {
    for (let i = 0; i < 5; i++) sink = implementation.fn()
    results.set(implementation.key, {
      ...implementation,
      iterations: calibratedIterations(implementation.fn, targetMs),
      timings: [],
    })
  }

  for (let sample = 0; sample < samples; sample++) {
    const offset = sample % implementations.length
    const order = implementations
      .slice(offset)
      .concat(implementations.slice(0, offset))
    for (const implementation of order) {
      const result = results.get(implementation.key)
      result.timings.push(runBatch(implementation.fn, result.iterations))
    }
  }

  for (const result of results.values()) {
    result.ms = median(result.timings)
    result.ops = (result.iterations * 1000) / result.ms
  }
  return results
}

function throughputRow(name, results) {
  const ours = results.get("ours")
  const legacy = results.get("legacy")
  const v2 = results.get("v2")
  return {
    case: name,
    "sm-cipher ops/s": Math.round(ours.ops),
    "sm-crypto ops/s": legacy ? Math.round(legacy.ops) : "-",
    "sm-crypto-v2 ops/s": v2 ? Math.round(v2.ops) : "-",
    "ours/v2": v2 ? `${(ours.ops / v2.ops).toFixed(2)}x` : "-",
  }
}

function implementations(ours, legacy, v2) {
  const entries = [{ key: "ours", fn: ours }]
  if (legacy) entries.push({ key: "legacy", fn: legacy })
  if (v2) entries.push({ key: "v2", fn: v2 })
  return entries
}

function runThroughputBenchmarks() {
  const privateHex =
    "75b25a5d6101013e9be25816f81cf1f64bf78ea8383b32d61f5b26e6f1429e70"
  const privateKey = hexToBytes(privateHex)
  const publicKey = getPublicKeyFromPrivateKey(privateKey)
  const publicHex = bytesToHex(publicKey)
  const preparedPublicKey = precomputePublicKey(publicKey, 4)
  const optimizedPublicKey = optimized.sm2.precomputePublicKey(publicHex, 4)
  const keyHex = "0123456789abcdeffedcba9876543210"
  const ivHex = "000102030405060708090a0b0c0d0e0f"
  const key = hexToBytes(keyHex)
  const iv = hexToBytes(ivHex)
  const data = Uint8Array.from({ length: 4096 }, (_, i) => i & 255)
  const oldData = Array.from(data)
  const message = utf8ToBytes(
    "SM2 interoperability benchmark: " + "abc".repeat(32)
  )
  const oldMessage = Array.from(message)

  const cipher = sm2Encrypt(message, publicKey)
  const legacyCipher = original.sm2.doEncrypt(oldMessage, publicHex)
  const optimizedCipher = optimized.sm2.doEncrypt(message, publicHex)
  const signature = sm2Sign(message, privateKey)
  const legacySignature = original.sm2.doSignature(oldMessage, privateHex, {
    hash: true,
  })
  const optimizedSignature = optimized.sm2.doSignature(message, privateHex, {
    hash: true,
  })

  const ecbCipher = sm4Encrypt(data, key)
  const legacyEcbCipher = original.sm4.encrypt(oldData, keyHex, {
    output: "array",
  })
  const optimizedEcbCipher = optimized.sm4.encrypt(data, key, {
    output: "array",
  })
  const cbcCipher = sm4Encrypt(data, key, { mode: "cbc", iv })
  const legacyCbcCipher = original.sm4.encrypt(oldData, keyHex, {
    mode: "cbc",
    iv: ivHex,
    output: "array",
  })
  const optimizedCbcCipher = optimized.sm4.encrypt(data, key, {
    mode: "cbc",
    iv,
    output: "array",
  })
  const gcmCipher = sm4Encrypt(data, key, { mode: "gcm", iv })
  const optimizedGcmCipher = optimized.sm4.encrypt(data, key, {
    mode: "gcm",
    iv,
    output: "array",
    outputTag: true,
  })

  const coreCases = [
    [
      "SM2 generateKeyPair",
      implementations(
        () => {
          const pair = generateKeyPair()
          return bytesToHex(pair.privateKey) + bytesToHex(pair.publicKey)
        },
        () => {
          const pair = original.sm2.generateKeyPairHex()
          return pair.privateKey + pair.publicKey
        },
        () => {
          const pair = optimized.sm2.generateKeyPairHex()
          return pair.privateKey + pair.publicKey
        }
      ),
    ],
    [
      "SM2 encrypt",
      implementations(
        () => bytesToHex(sm2Encrypt(message, publicKey)),
        () => original.sm2.doEncrypt(oldMessage, publicHex),
        () => optimized.sm2.doEncrypt(message, publicHex)
      ),
    ],
    [
      "SM2 encrypt (precomputed key)",
      implementations(
        () => bytesToHex(sm2Encrypt(message, preparedPublicKey)),
        null,
        () => optimized.sm2.doEncrypt(message, optimizedPublicKey)
      ),
    ],
    [
      "SM2 decrypt",
      implementations(
        () => sm2Decrypt(cipher, privateKey),
        () =>
          original.sm2.doDecrypt(legacyCipher, privateHex, 1, {
            output: "array",
          }),
        () =>
          optimized.sm2.doDecrypt(optimizedCipher, privateHex, 1, {
            output: "array",
          })
      ),
    ],
    [
      "SM2 sign",
      implementations(
        () => bytesToHex(sm2Sign(message, privateKey)),
        () =>
          original.sm2.doSignature(oldMessage, privateHex, { hash: true }),
        () =>
          optimized.sm2.doSignature(message, privateHex, { hash: true })
      ),
    ],
    [
      "SM2 sign (supplied public key)",
      implementations(
        () => bytesToHex(sm2Sign(message, privateKey, { publicKey })),
        () =>
          original.sm2.doSignature(oldMessage, privateHex, {
            hash: true,
            publicKey: publicHex,
          }),
        () =>
          optimized.sm2.doSignature(message, privateHex, {
            hash: true,
            publicKey: publicHex,
          })
      ),
    ],
    [
      "SM2 verify",
      implementations(
        () => sm2Verify(message, signature, publicKey),
        () =>
          original.sm2.doVerifySignature(
            oldMessage,
            legacySignature,
            publicHex,
            { hash: true }
          ),
        () =>
          optimized.sm2.doVerifySignature(
            message,
            optimizedSignature,
            publicHex,
            { hash: true }
          )
      ),
    ],
    [
      "SM3 4 KiB (hex output)",
      implementations(
        () => bytesToHex(sm3(data)),
        () => original.sm3(oldData),
        () => optimized.sm3(data)
      ),
    ],
    [
      "SM4 ECB encrypt 4 KiB",
      implementations(
        () => sm4Encrypt(data, key),
        () => original.sm4.encrypt(oldData, keyHex, { output: "array" }),
        () => optimized.sm4.encrypt(data, key, { output: "array" })
      ),
    ],
    [
      "SM4 ECB decrypt 4 KiB",
      implementations(
        () => sm4Decrypt(ecbCipher, key),
        () =>
          original.sm4.decrypt(legacyEcbCipher, keyHex, { output: "array" }),
        () =>
          optimized.sm4.decrypt(optimizedEcbCipher, key, { output: "array" })
      ),
    ],
    [
      "SM4 CBC encrypt 4 KiB",
      implementations(
        () => sm4Encrypt(data, key, { mode: "cbc", iv }),
        () =>
          original.sm4.encrypt(oldData, keyHex, {
            mode: "cbc",
            iv: ivHex,
            output: "array",
          }),
        () =>
          optimized.sm4.encrypt(data, key, {
            mode: "cbc",
            iv,
            output: "array",
          })
      ),
    ],
    [
      "SM4 CBC decrypt 4 KiB",
      implementations(
        () => sm4Decrypt(cbcCipher, key, { mode: "cbc", iv }),
        () =>
          original.sm4.decrypt(legacyCbcCipher, keyHex, {
            mode: "cbc",
            iv: ivHex,
            output: "array",
          }),
        () =>
          optimized.sm4.decrypt(optimizedCbcCipher, key, {
            mode: "cbc",
            iv,
            output: "array",
          })
      ),
    ],
    [
      "SM4 GCM encrypt 4 KiB",
      implementations(
        () => sm4Encrypt(data, key, { mode: "gcm", iv }),
        null,
        () =>
          optimized.sm4.encrypt(data, key, {
            mode: "gcm",
            iv,
            output: "array",
            outputTag: true,
          })
      ),
    ],
    [
      "SM4 GCM decrypt 4 KiB",
      implementations(
        () =>
          sm4Decrypt(gcmCipher.output, key, {
            mode: "gcm",
            iv,
            tag: gcmCipher.tag,
          }),
        null,
        () =>
          optimized.sm4.decrypt(optimizedGcmCipher.output, key, {
            mode: "gcm",
            iv,
            tag: optimizedGcmCipher.tag,
            output: "array",
          })
      ),
    ],
  ]

  console.log("\nEnd-to-end public API throughput")
  console.log(
    `Each sample is auto-calibrated to about ${sampleDurationMs} ms; ${samples} samples; median; execution order rotates per sample.`
  )
  const coreRows = coreCases.map(([name, entries]) =>
    throughputRow(name, measureGroup(entries))
  )
  console.table(coreRows)

  const sizeRows = []
  const sizeTargetMs = Math.max(75, sampleDurationMs / 2)
  for (const length of [64, 65536]) {
    const input = Uint8Array.from({ length }, (_, i) => i & 255)
    const oursEcb = sm4Encrypt(input, key)
    const v2Ecb = optimized.sm4.encrypt(input, key, { output: "array" })
    const oursCbc = sm4Encrypt(input, key, { mode: "cbc", iv })
    const v2Cbc = optimized.sm4.encrypt(input, key, {
      mode: "cbc",
      iv,
      output: "array",
    })
    const label = length === 64 ? "64 B" : "64 KiB"
    const cases = [
      [
        `SM3 ${label} (hex output)`,
        implementations(
          () => bytesToHex(sm3(input)),
          null,
          () => optimized.sm3(input)
        ),
      ],
      [
        `SM4 ECB encrypt ${label}`,
        implementations(
          () => sm4Encrypt(input, key),
          null,
          () => optimized.sm4.encrypt(input, key, { output: "array" })
        ),
      ],
      [
        `SM4 ECB decrypt ${label}`,
        implementations(
          () => sm4Decrypt(oursEcb, key),
          null,
          () => optimized.sm4.decrypt(v2Ecb, key, { output: "array" })
        ),
      ],
      [
        `SM4 CBC decrypt ${label}`,
        implementations(
          () => sm4Decrypt(oursCbc, key, { mode: "cbc", iv }),
          null,
          () =>
            optimized.sm4.decrypt(v2Cbc, key, {
              mode: "cbc",
              iv,
              output: "array",
            })
        ),
      ],
    ]
    for (const [name, entries] of cases)
      sizeRows.push(throughputRow(name, measureGroup(entries, sizeTargetMs)))
  }
  console.log("\nPayload-size sensitivity")
  console.table(sizeRows)
}

function coldWorkerSource(target) {
  const sourceUrl = pathToFileURL(resolve("dist/smcrypto.js")).href
  const setup =
    target === "ours"
      ? `const api = await import(${JSON.stringify(sourceUrl)}); const seed = Uint8Array.of(1); const generate = () => api.generateKeyPair(seed);`
      : `const {createRequire} = await import("node:module"); const require = createRequire(import.meta.url); const api = require("sm-crypto-v2"); const generate = () => api.sm2.generateKeyPairHex("1");`
  return `
    import {performance} from "node:perf_hooks";
    const memory = () => process.memoryUsage();
    const settle = async () => {
      for (let i = 0; i < 3; i++) {
        await new Promise((resolve) => setImmediate(resolve));
        globalThis.gc();
      }
    };
    await settle();
    const beforeImport = memory();
    const importStart = performance.now();
    ${setup}
    const importMs = performance.now() - importStart;
    await settle();
    const afterImport = memory();
    const firstStart = performance.now();
    let sink = generate();
    const firstCallMs = performance.now() - firstStart;
    const afterFirstImmediate = memory();
    sink = undefined;
    await settle();
    const afterFirst = memory();
    const warmIterations = 25;
    const warmStart = performance.now();
    for (let i = 0; i < warmIterations; i++) sink = generate();
    const warmCallMs = (performance.now() - warmStart) / warmIterations;
    console.log(JSON.stringify({
      importMs,
      firstCallMs,
      warmCallMs,
      importHeapKiB: (afterImport.heapUsed - beforeImport.heapUsed) / 1024,
      firstCallHeapKiB: (afterFirstImmediate.heapUsed - afterImport.heapUsed) / 1024,
      retainedHeapKiB: (afterFirst.heapUsed - afterImport.heapUsed) / 1024,
      retainedRssKiB: (afterFirst.rss - afterImport.rss) / 1024
    }));
    void sink;
  `
}

function measureColdStart(target) {
  const observations = []
  for (let i = 0; i < coldSamples; i++) {
    const child = spawnSync(
      process.execPath,
      [
        "--no-warnings",
        "--expose-gc",
        "--input-type=module",
        "--eval",
        coldWorkerSource(target),
      ],
      { cwd: process.cwd(), encoding: "utf8", timeout: 60000 }
    )
    if (child.status !== 0)
      throw new Error(
        `Cold-start worker failed for ${target}: ${child.stderr || child.stdout}`
      )
    const line = child.stdout.trim().split(/\r?\n/).at(-1)
    observations.push(JSON.parse(line))
  }
  const metric = (name) => median(observations.map((value) => value[name]))
  return {
    importMs: metric("importMs"),
    firstCallMs: metric("firstCallMs"),
    warmCallMs: metric("warmCallMs"),
    importHeapKiB: metric("importHeapKiB"),
    firstCallHeapKiB: metric("firstCallHeapKiB"),
    retainedHeapKiB: metric("retainedHeapKiB"),
    retainedRssKiB: metric("retainedRssKiB"),
  }
}

function signed(value, digits = 0) {
  return `${value >= 0 ? "+" : ""}${value.toFixed(digits)}`
}

function runStartupBenchmarks() {
  console.log("\nCold start and retained memory")
  console.log(
    `Fresh child process per sample; ${coldSamples} samples; median; --expose-gc. sm-cipher uses a lazy 5-bit signed base table with 53 x 17 slots.`
  )
  const rows = [
    ["sm-cipher", measureColdStart("ours")],
    [optimizedShortName, measureColdStart("v2")],
  ].map(([library, result]) => ({
    library,
    "import ms": result.importMs.toFixed(2),
    "first keypair ms": result.firstCallMs.toFixed(2),
    "warm keypair ms": result.warmCallMs.toFixed(2),
    "import heap KiB": signed(result.importHeapKiB),
    "first-call heap growth KiB": signed(result.firstCallHeapKiB),
    "first-call retained heap KiB": signed(result.retainedHeapKiB),
    "first-call retained RSS KiB": signed(result.retainedRssKiB),
  }))
  console.table(rows)
  console.log(
    "Retained deltas include lazy compilation and allocator effects in addition to the base table; treat them as process-level estimates."
  )
}

console.log(
  `Node ${process.version}; ${process.platform}/${process.arch}; ${cpus()[0]?.model}`
)
console.log(
  `Comparison: ${referenceName}, ${optimizedName} (${optimizedShortName})`
)
if (!startupOnly) runThroughputBenchmarks()
if (!throughputOnly) runStartupBenchmarks()
void sink
