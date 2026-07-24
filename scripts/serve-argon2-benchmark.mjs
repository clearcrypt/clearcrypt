#!/usr/bin/env node
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync, rmSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { mkdtempSync } from "node:fs";
import { build } from "esbuild";

function readOption(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

const positionalPort = process.argv[2]?.startsWith("--")
  ? undefined
  : process.argv[2];
const port = Number(readOption("--port") ?? positionalPort ?? 4173);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  throw new Error("Port must be an integer between 1 and 65535");
}
const certificatePath = readOption("--cert");
const privateKeyPath = readOption("--key");
if (Boolean(certificatePath) !== Boolean(privateKeyPath)) {
  throw new Error("--cert and --key must be supplied together");
}

const root = resolve("benchmarks/argon2/browser");
const outputDirectory = mkdtempSync(join(tmpdir(), "clearcrypt-argon2-"));

await build({
  entryPoints: {
    main: join(root, "main.js"),
    worker: join(root, "worker.js"),
  },
  outdir: outputDirectory,
  bundle: true,
  platform: "browser",
  format: "esm",
  target: "es2022",
});

const assets = new Map([
  ["/", { type: "text/html; charset=utf-8", body: readFileSync(join(root, "index.html")) }],
  ["/main.js", { type: "text/javascript; charset=utf-8", body: readFileSync(join(outputDirectory, "main.js")) }],
  ["/worker.js", { type: "text/javascript; charset=utf-8", body: readFileSync(join(outputDirectory, "worker.js")) }],
]);

const handleRequest = (request, response) => {
  const asset = assets.get(request.url ?? "/");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  response.setHeader("Cache-Control", "no-store");
  if (!asset) {
    response.writeHead(404).end("Not found");
    return;
  }
  response.setHeader("Content-Type", asset.type);
  response.writeHead(200).end(asset.body);
};

const useTls = certificatePath !== undefined && privateKeyPath !== undefined;
const server = useTls
  ? createHttpsServer(
      {
        cert: readFileSync(resolve(certificatePath)),
        key: readFileSync(resolve(privateKeyPath)),
      },
      handleRequest
    )
  : createHttpServer(handleRequest);

server.listen(port, "0.0.0.0", () => {
  const scheme = useTls ? "https" : "http";
  console.log(`Local benchmark: ${scheme}://localhost:${port}`);
  if (useTls) {
    for (const addresses of Object.values(networkInterfaces())) {
      for (const address of addresses ?? []) {
        if (address.family === "IPv4" && !address.internal) {
          console.log(`Network benchmark: ${scheme}://${address.address}:${port}`);
        }
      }
    }
  } else {
    console.log(
      "LAN/mobile testing requires trusted HTTPS: restart with --cert and --key."
    );
  }
  console.log("Press Ctrl+C to stop.");
});

function shutdown() {
  server.close(() => {
    rmSync(outputDirectory, { recursive: true, force: true });
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
