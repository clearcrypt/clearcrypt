import { decryptBytesV1, encryptBytesV1 } from "../../dist/browser.js";

const toBytes = (values) => new Uint8Array(values);
const toValues = (bytes) => Array.from(bytes);

self.addEventListener("message", async ({ data }) => {
  try {
    if (data.notifyStarted) {
      self.postMessage({ started: true });
    }

    let value;
    switch (data.action) {
      case "encrypt": {
        value = toValues(
          await encryptBytesV1(
            toBytes(data.plaintext),
            data.password,
            data.options
          )
        );
        break;
      }
      case "roundTrip": {
        const archive = await encryptBytesV1(
          toBytes(data.plaintext),
          data.password
        );
        value = toValues(await decryptBytesV1(archive, data.password));
        break;
      }
      default:
        throw new Error(`Unknown worker action: ${String(data.action)}`);
    }
    self.postMessage({ ok: true, value });
  } catch (error) {
    self.postMessage({
      ok: false,
      error: {
        name: error instanceof Error ? error.name : typeof error,
        code: error?.code ?? null,
        message: error instanceof Error ? error.message : String(error),
      },
    });
  }
});
