import { spawnSync } from "node:child_process";

const expectedFiles = [
  "LICENSE",
  "README.md",
  "dist/index.d.ts",
  "dist/index.js",
  "docs/format-v1.md",
  "docs/memory-v1.md",
  "package.json",
  "scripts/benchmark-memory-v1.mjs",
  "scripts/cc-file.mjs",
  "scripts/cli-password.mjs",
  "scripts/verify-v1-vector.mjs",
  "test/vectors/v1/unicode-password-binary-plaintext.json",
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
