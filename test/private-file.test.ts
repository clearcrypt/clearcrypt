import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

// The CLI helper is intentionally plain JavaScript, shipped alongside cc-file.
// @ts-expect-error No declaration file is required for this internal CLI module.
import { writePrivateFileAtomic } from "../scripts/private-file.mjs";

vi.mock("node:crypto", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:crypto")>(),
  randomUUID: () => "00000000-0000-4000-8000-000000000000",
}));

describe("private atomic CLI output", () => {
  let directory: string;
  beforeAll(() => { directory = mkdtempSync(join(process.cwd(), ".clearcrypt-private-")); });
  afterAll(() => { rmSync(directory, { recursive: true, force: true }); });

  it("replaces the output only after a complete write", () => {
    const target = join(directory, "output.bin");
    writeFileSync(target, "old");
    writePrivateFileAtomic(target, Buffer.from("new"));
    expect(readFileSync(target, "utf8")).toBe("new");
    expect(readdirSync(directory).some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("preserves both the destination and a colliding temporary path", () => {
    const target = join(directory, "collision.bin");
    const temporary = join(directory,
      `.collision.bin.clearcrypt-${process.pid}-00000000-0000-4000-8000-000000000000.tmp`);
    writeFileSync(target, "destination");
    writeFileSync(temporary, "temporary");
    expect(() => writePrivateFileAtomic(target, Buffer.from("new"))).toThrow();
    expect(readFileSync(target, "utf8")).toBe("destination");
    expect(readFileSync(temporary, "utf8")).toBe("temporary");
    rmSync(temporary);
  });

  it("cleans up its own temporary file after a failed write", () => {
    const target = join(directory, "failure.bin");
    writeFileSync(target, "destination");
    expect(() => writePrivateFileAtomic(target, {})).toThrow();
    expect(readFileSync(target, "utf8")).toBe("destination");
    expect(readdirSync(directory).some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it.skipIf(process.platform === "win32")("does not follow a destination symlink and restricts permissions", () => {
    const victim = join(directory, "victim.bin");
    const target = join(directory, "symlink.bin");
    writeFileSync(victim, "victim");
    symlinkSync(victim, target);
    const previousUmask = process.umask(0);
    try { writePrivateFileAtomic(target, Buffer.from("private")); }
    finally { process.umask(previousUmask); }
    expect(readFileSync(victim, "utf8")).toBe("victim");
    expect(readFileSync(target, "utf8")).toBe("private");
    expect(statSync(target).mode & 0o777).toBe(0o600);
  });
});
