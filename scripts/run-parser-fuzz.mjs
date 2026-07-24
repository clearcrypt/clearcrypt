#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

function readOption(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function readPositiveInteger(name, fallback) {
  const value = Number(readOption(name, fallback));
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

const runs = readPositiveInteger("--runs", 10_000);
const seed = readPositiveInteger("--seed", 0x0cf001);
const vitest = resolve("node_modules/vitest/vitest.mjs");
const result = spawnSync(
  process.execPath,
  [vitest, "run", "test/fuzz-parser.v1.test.ts"],
  {
    cwd: process.cwd(),
    env: {
      ...process.env,
      CLEARCRYPT_FUZZ_RUNS: String(runs),
      CLEARCRYPT_FUZZ_SEED: String(seed),
    },
    stdio: "inherit",
    shell: false,
  }
);

if (result.error) {
  throw result.error;
}
process.exit(result.status ?? 1);
