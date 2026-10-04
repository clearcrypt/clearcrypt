import { PassThrough } from "node:stream";

import { describe, expect, it, vi } from "vitest";

import { readConfirmedPassword, readPassword } from "../scripts/cli-password.mjs";

function fakeTerminal() {
  const input = new PassThrough();
  Object.defineProperty(input, "isTTY", { value: true });
  input.isRaw = false;
  input.setRawMode = vi.fn((value) => {
    input.isRaw = value;
  });
  const output = new PassThrough();
  return { input, output };
}

describe("interactive CLI password lifecycle", () => {
  it("pauses the terminal after decryption password input", async () => {
    const { input, output } = fakeTerminal();
    const password = readPassword("Password: ", input, output);

    input.write("decrypt-secret\r");

    await expect(password).resolves.toBe("decrypt-secret");
    expect(input.isPaused()).toBe(true);
    expect(input.isRaw).toBe(false);
    input.destroy();
    output.destroy();
  });

  it("pauses the terminal after encryption password confirmation", async () => {
    const { input, output } = fakeTerminal();
    const password = readConfirmedPassword(input, output);

    input.write("encrypt-secret\r");
    await new Promise((resolve) => setImmediate(resolve));
    input.write("encrypt-secret\r");

    await expect(password).resolves.toBe("encrypt-secret");
    expect(input.isPaused()).toBe(true);
    expect(input.isRaw).toBe(false);
    input.destroy();
    output.destroy();
  });
});
