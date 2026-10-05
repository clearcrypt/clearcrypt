import { spawnSync } from "node:child_process";

const expectedFiles = [
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "benchmarks/argon2/browser/index.html",
  "benchmarks/argon2/browser/main.js",
  "benchmarks/argon2/browser/worker.js",
  "dist/browser.js",
  "dist/benchmark-v2-internal.d.ts",
  "dist/benchmark-v2-internal.js",
  "dist/index.d.ts",
  "dist/index.js",
  "dist/node.d.ts",
  "dist/node.js",
  "docs/argon2-profiles-v1.md",
  "docs/guide-v2.md",
  "docs/qualification-v2.md",
  "docs/results/qualification-v2-node-2026-10-04.json",
  "docs/format-v1.md",
  "docs/format-v2.md",
  "docs/memory-v1.md",
  "package.json",
  "scripts/benchmark-memory-v1.mjs",
  "scripts/benchmark-v2.mjs",
  "scripts/qualify-v2.mjs",
  "scripts/run-browser-qualification-v2.mjs",
  "scripts/benchmark-argon2-v1.mjs",
  "scripts/cc-file.mjs",
  "scripts/cli-password.mjs",
  "scripts/private-file.mjs",
  "scripts/serve-argon2-benchmark.mjs",
  "scripts/verify-v1-vector.mjs",
  "scripts/verify-v2-vectors.mjs",
  "test/vectors/v1/unicode-password-binary-plaintext.json",
  "test/vectors/v2/empty.json",
  "test/vectors/v2/multiple-blocks.json",
  "test/vectors/v2/unicode-binary.json",
].sort();

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  throw new Error("Run this verifier through npm run check:package");
}

const result = spawnSync(
  process.execPath,
  [npmCli, "pack", "--dry-run", "--json"],
  {
    cwd: process.cwd(),
    encoding: "utf8",
    shell: false,
  }
);

if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  process.stderr.write(result.stderr);
  process.exit(result.status ?? 1);
}

let report;
try {
  report = JSON.parse(result.stdout);
} catch (cause) {
  throw new Error("npm pack did not return valid JSON", { cause });
}

if (!Array.isArray(report) || report.length !== 1 || !Array.isArray(report[0]?.files)) {
  throw new Error("npm pack returned an unexpected report");
}

const actualFiles = report[0].files.map(({ path }) => path).sort();
const generatedV2TypeFiles = actualFiles.filter((path) =>
  /^dist\/stream-types-[A-Za-z0-9_-]+\.d\.ts$/.test(path)
);
if (generatedV2TypeFiles.length !== 1) {
  console.error(
    `Expected one generated V2 type declaration, found ${generatedV2TypeFiles.length}`
  );
  process.exit(1);
}
expectedFiles.push(generatedV2TypeFiles[0]);
expectedFiles.sort();
const missing = expectedFiles.filter((path) => !actualFiles.includes(path));
const unexpected = actualFiles.filter((path) => !expectedFiles.includes(path));

if (missing.length > 0 || unexpected.length > 0) {
  if (missing.length > 0) {
    console.error(`Missing package files:\n${missing.join("\n")}`);
  }
  if (unexpected.length > 0) {
    console.error(`Unexpected package files:\n${unexpected.join("\n")}`);
  }
  process.exit(1);
}

console.log(`Verified npm package contents (${actualFiles.length} files)`);
