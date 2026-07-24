#!/usr/bin/env node
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, resolve } from "node:path";
import { build } from "esbuild";

const host = "127.0.0.1";
const port = 4176;
const root = resolve(".");
const outputDirectory = mkdtempSync(join(tmpdir(), "clearcrypt-browser-tests-"));

await build({
  entryPoints: {
    harness: resolve(root, "test/browser/harness.js"),
    "crypto.worker": resolve(root, "test/browser/crypto.worker.js"),
  },
  outdir: outputDirectory,
  bundle: true,
  platform: "browser",
  format: "esm",
  target: "es2022",
});

const allowedFiles = new Map([
  ["/", resolve(root, "test/browser/harness.html")],
  ["/harness.js", resolve(outputDirectory, "harness.js")],
  ["/crypto.worker.js", resolve(outputDirectory, "crypto.worker.js")],
]);
const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

const server = createServer((request, response) => {
  const file = allowedFiles.get(request.url ?? "/");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  response.setHeader("Cache-Control", "no-store");
  if (!file) {
    response.writeHead(404).end("Not found");
    return;
  }

  response.setHeader(
    "Content-Type",
    contentTypes[extname(file)] ?? "application/octet-stream"
  );
  response.writeHead(200).end(readFileSync(file));
});

server.listen(port, host, () => {
  console.log(`Browser test server: http://${host}:${port}`);
});

function shutdown() {
  server.close(() => {
    rmSync(outputDirectory, { recursive: true, force: true });
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
