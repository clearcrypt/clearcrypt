#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const index = process.argv.indexOf("--size-mib");
const sizeMiB = Number(index === -1 ? 64 : process.argv[index + 1]);
if (!Number.isSafeInteger(sizeMiB) || sizeMiB <= 0) {
  throw new Error("--size-mib must be a positive integer");
}

const playwright = resolve("node_modules/@playwright/test/cli.js");
const result = spawnSync(
  process.execPath,
  [playwright, "test", "test/browser/clearcrypt.browser.spec.ts"],
  {
    cwd: process.cwd(),
    env: {
      ...process.env,
      CLEARCRYPT_BROWSER_QUALIFICATION_MIB: String(sizeMiB),
    },
    stdio: "inherit",
    shell: false,
  }
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
