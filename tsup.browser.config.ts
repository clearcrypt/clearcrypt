import { defineConfig } from "tsup";
import { resolve } from "node:path";

export default defineConfig({
  entry: { browser: "src/index.ts" },
  format: ["esm"],
  platform: "browser",
  target: "es2022",
  dts: false,
  splitting: false,
  clean: false,
  esbuildPlugins: [
    {
      name: "clearcrypt-browser-argon2-adapter",
      setup(build) {
        build.onResolve(
          { filter: /^\.\/argon2\/runtime$/ },
          (args) => ({
            path: resolve(args.resolveDir, "argon2/runtime.browser.ts"),
          })
        );
      },
    },
  ],
});
