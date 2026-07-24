import { describe, expect, it } from "vitest";
import {
  getNodeArgon2WasmMetadata,
  hashArgon2idInNode,
} from "../src/v1/argon2/node";
import {
  ARGON2_VERSION_DECIMAL,
  ARGON2ID_TYPE,
} from "../src/v1/argon2/types";
import { bytes } from "./helpers";

const PARAMS = {
  password: new TextEncoder().encode("concurrent-password"),
  salt: bytes(16, (index) => 0x20 + index),
  timeCost: 1,
  memoryCostKiB: 8 * 1024,
  parallelism: 1,
  hashLengthBytes: 32,
};

describe("argon2-browser Node adapter", () => {
  it("initializes concurrently without leaking global mutations", async () => {
    const originalSelf = { owner: "test-self" };
    const originalModule = { owner: "test-module" };
    const originalLoader = () => Promise.resolve({ owner: "test-loader" });

    Object.defineProperty(globalThis, "self", {
      configurable: true,
      writable: true,
      value: originalSelf,
    });
    Object.defineProperty(globalThis, "Module", {
      configurable: true,
      writable: true,
      value: originalModule,
    });
    Object.defineProperty(globalThis, "loadArgon2WasmModule", {
      configurable: true,
      writable: true,
      value: originalLoader,
    });

    try {
      const results = await Promise.all(
        Array.from({ length: 6 }, () => hashArgon2idInNode(PARAMS))
      );

      for (const result of results) {
        expect(result.hash).toHaveLength(32);
        expect(result.hash).toEqual(results[0]!.hash);
        expect(result.encoded).toMatch(
          new RegExp(`^\\$argon2id\\$v=${ARGON2_VERSION_DECIMAL}\\$`)
        );
      }
      expect(ARGON2ID_TYPE).toBe(2);
      expect(globalThis.self).toBe(originalSelf);
      expect((globalThis as { Module?: unknown }).Module).toBe(originalModule);
      expect(
        (globalThis as { loadArgon2WasmModule?: unknown })
          .loadArgon2WasmModule
      ).toBe(originalLoader);
    } finally {
      Reflect.deleteProperty(globalThis, "self");
      Reflect.deleteProperty(globalThis, "Module");
      Reflect.deleteProperty(globalThis, "loadArgon2WasmModule");
    }
  });

  it("validates the audited WebAssembly binary", async () => {
    const metadata = await getNodeArgon2WasmMetadata();

    expect(metadata.byteLength).toBe(25_725);
    expect(metadata.sha256).toBe(
      "0c2149886c13e4eae4a6ca25ee71d47423c5c8740a874cf04ff816d1b2c901d7"
    );
  });
});
