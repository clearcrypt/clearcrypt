import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const node = process.execPath;
const helperUrl = pathToFileURL(resolve("scripts/cli-password.mjs")).href;
const cliPath = resolve("scripts/cc-file.mjs");

function probePassword(input: string) {
  const program = `
    import { readPassword } from ${JSON.stringify(helperUrl)};
    const value = await readPassword();
    process.stdout.write(Buffer.from(value, "utf8").toString("hex"));
  `;
  return spawnSync(node, ["--input-type=module", "--eval", program], {
    input: `${input}\n`,
    encoding: "utf8",
  });
}

describe("file CLI password handling", () => {
  it.each([
    "  leading and trailing  ",
    "Café",
    "emoji 🔐",
    "e\u0301",
  ])("preserves the exact piped password %j without logging it", (password) => {
    const result = probePassword(password);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(Buffer.from(password, "utf8").toString("hex"));
    expect(result.stderr).toBe("Password: ");
    expect(result.stderr).not.toContain(password);
  });

  it("requires matching confirmation for encryption", () => {
    const first = "  secret-Café🔐  ";
    const second = "different";
    const result = spawnSync(
      node,
      [cliPath, "encrypt", "missing-input", "unused-output"],
      { input: `${first}\n${second}\n`, encoding: "utf8" }
    );

    expect(result.status).toBe(65);
    expect(result.stderr).toContain("PASSWORD_MISMATCH");
    expect(result.stderr).not.toContain(first);
    expect(result.stderr).not.toContain(second);
  });

  it("accepts an exact confirmation without trimming it", () => {
    const password = "  Café🔐 e\u0301  ";
    const result = spawnSync(
      node,
      [cliPath, "encrypt", "missing-input", "unused-output"],
      { input: `${password}\n${password}\n`, encoding: "utf8" }
    );

    expect(result.status).toBe(66);
    expect(result.stderr).toContain("INPUT_ERROR");
    expect(result.stderr).not.toContain("PASSWORD_MISMATCH");
    expect(result.stderr).not.toContain(password);
  });

  it("uses a stable usage exit code", () => {
    const result = spawnSync(node, [cliPath], { encoding: "utf8" });

    expect(result.status).toBe(64);
    expect(result.stderr).toContain("Usage:");
  });
});
