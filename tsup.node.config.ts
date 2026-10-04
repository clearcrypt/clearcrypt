import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    node: "src/node.ts",
    "benchmark-v2-internal": "src/benchmark-v2-internal.ts",
  },
  format: ["esm"],
  platform: "node",
  target: "es2022",
  dts: true,
  splitting: false,
  clean: true,
});
