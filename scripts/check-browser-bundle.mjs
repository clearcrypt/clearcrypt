import { build } from "esbuild";

const result = await build({
  entryPoints: ["dist/browser.js"],
  bundle: true,
  platform: "browser",
  format: "esm",
  write: false,
  logLevel: "silent",
});

if (result.outputFiles.length !== 1) {
  throw new Error("Expected one browser bundle output");
}

console.log(
  `Verified browser bundle (${result.outputFiles[0].contents.byteLength} bytes)`
);
