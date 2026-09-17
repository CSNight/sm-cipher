import { resolve } from "path"
import { defineConfig } from "vite"

export default defineConfig({
  build: {
    target: "es2020",
    sourcemap: false,
    minify: "oxc",
    lib: {
      entry: resolve(import.meta.dirname, "src/index.ts"),
      formats: ["es"],
      fileName: () => "smcrypto.js",
    },
  },
})
