import { describe, expect, it } from "vitest";
import { unwrapDekWithKek, wrapDekWithKek } from "../src/v1/wrap";
import { bytes } from "./helpers";

describe("V1 wrap (DEK with KEK)", () => {
  it("wraps then unwraps the same DEK", async () => {
    const dek = bytes(32, (i) => 0x10 + i);
    const kekRaw32 = bytes(32, (i) => 0x80 + i);
    const wrapNonce = bytes(12, (i) => 0x20 + i);

    const wrap = await wrapDekWithKek({ dek, kekRaw32, wrapNonce });
    const unwrapped = await unwrapDekWithKek({ wrap, kekRaw32 });

    expect([...unwrapped]).toEqual([...dek]);
  });

  it("fails with wrong KEK", async () => {
    const dek = bytes(32, (i) => 0x11 + i);
    const kekRaw32 = bytes(32, (i) => 0x44 + i);
    const wrongKek = bytes(32, (i) => 0x55 + i);
    const wrapNonce = bytes(12, (i) => 0x33 + i);

    const wrap = await wrapDekWithKek({ dek, kekRaw32, wrapNonce });

    await expect(unwrapDekWithKek({ wrap, kekRaw32: wrongKek })).rejects.toThrow();
  });

  it("fails if wrap tag is tampered", async () => {
    const dek = bytes(32, (i) => 0x22 + i);
    const kekRaw32 = bytes(32, (i) => 0x66 + i);
    const wrapNonce = bytes(12, (i) => 0x44 + i);

    const wrap = await wrapDekWithKek({ dek, kekRaw32, wrapNonce });
    const tampered = { ...wrap, wrapTag: wrap.wrapTag.slice() };
    tampered.wrapTag[0] = (tampered.wrapTag[0]! ^ 0xff) & 0xff;

    await expect(unwrapDekWithKek({ wrap: tampered, kekRaw32 })).rejects.toThrow();
  });
});
