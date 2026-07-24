import { KDF_PROFILES_V1, encryptBytesV1 } from "../../../dist/browser.js";

async function encryptOnce(profileId) {
  const { version: _version, ...kdf } = KDF_PROFILES_V1[profileId];
  const startedAt = performance.now();
  await encryptBytesV1(
    new Uint8Array(),
    "clearcrypt-argon2-benchmark",
    { kdf }
  );
  return performance.now() - startedAt;
}

self.addEventListener("message", async ({ data }) => {
  try {
    await encryptOnce(data.profileId);
    const durationsMs = [];
    for (let index = 0; index < data.runs; index++) {
      durationsMs.push(await encryptOnce(data.profileId));
    }
    self.postMessage({ ok: true, durationsMs });
  } catch (error) {
    self.postMessage({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
