import { expect, test } from "@playwright/test";

import { decryptBytesV1, encryptBytesV1 } from "../../dist/index.js";

const password = "correct horse battery staple 🔐";
const plaintext = [0, 1, 2, 127, 128, 254, 255, 42];

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#ready")).toHaveText("ready");
});

test("opens a Node archive in the browser", async ({ page }) => {
  const archive = Array.from(
    await encryptBytesV1(new Uint8Array(plaintext), password)
  );

  const decrypted = await page.evaluate(
    ({ archive, password }) =>
      window.clearcryptTest.decrypt(archive, password),
    { archive, password }
  );

  expect(decrypted).toEqual(plaintext);
});

test("opens a browser archive under Node", async ({ page }) => {
  const archive = await page.evaluate(
    ({ plaintext, password }) =>
      window.clearcryptTest.encrypt(plaintext, password),
    { plaintext, password }
  );

  const decrypted = await decryptBytesV1(new Uint8Array(archive), password);
  expect(Array.from(decrypted)).toEqual(plaintext);
});

test("runs encryption and decryption in a Web Worker", async ({ page }) => {
  const decrypted = await page.evaluate(
    ({ plaintext, password }) =>
      window.clearcryptTest.workerRoundTrip(plaintext, password),
    { plaintext, password }
  );

  expect(decrypted).toEqual(plaintext);
});

test("serializes concurrent Argon2 calls without corrupting results", async ({
  page,
}) => {
  const payloads = [
    plaintext,
    [...plaintext].reverse(),
    [9, 8, 7, 6, 5, 4, 3],
  ];

  const decrypted = await page.evaluate(
    ({ payloads, password }) =>
      window.clearcryptTest.concurrentRoundTrips(payloads, password),
    { payloads, password }
  );

  expect(decrypted).toEqual(payloads);
});

test("returns stable public errors for invalid browser decryptions", async ({
  page,
}) => {
  const archive = Array.from(
    await encryptBytesV1(new Uint8Array(plaintext), password)
  );
  const tampered = [...archive];
  tampered[tampered.length - 1] = (tampered.at(-1) ?? 0) ^ 1;

  const [wrongPassword, alteredArchive, invalidFormat, resourceLimit] =
    await page.evaluate(
      async ({ archive, tampered, password }) =>
        Promise.all([
          window.clearcryptTest.captureDecryptError(archive, "wrong password"),
          window.clearcryptTest.captureDecryptError(tampered, password),
          window.clearcryptTest.captureDecryptError([1, 2, 3], password),
          window.clearcryptTest.captureDecryptError(archive, password, {
            resourcePolicy: {
              maxMemoryCostKiB: 1,
              maxTimeCost: 1,
              maxParallelism: 1,
            },
          }),
        ]),
      { archive, tampered, password }
    );

  expect(wrongPassword?.code).toBe("AUTH_FAILED");
  expect(alteredArchive?.code).toBe("AUTH_FAILED");
  expect(invalidFormat?.code).toBe("INVALID_FORMAT");
  expect(resourceLimit?.code).toBe("RESOURCE_LIMIT");
});

test("cancels an in-flight Worker by terminating it", async ({ page }) => {
  await page.evaluate(() => window.clearcryptTest.startCancelableWorker());
  const pending = page
    .evaluate(() => window.clearcryptTest.waitForCancelableWorker())
    .then(
      () => ({ resolved: true, name: null, message: null }),
      (error: Error) => ({
        resolved: false,
        name: error.name,
        message: error.message,
      })
    );
  await page.evaluate(() => window.clearcryptTest.cancelWorker());

  await expect(pending).resolves.toEqual({
    resolved: false,
    name: "Error",
    message: expect.stringContaining("Worker operation aborted"),
  });
});

declare global {
  interface Window {
    clearcryptTest: {
      decrypt(
        archive: number[],
        password: string,
        options?: object
      ): Promise<number[]>;
      encrypt(
        plaintext: number[],
        password: string,
        options?: object
      ): Promise<number[]>;
      captureDecryptError(
        archive: number[],
        password: string,
        options?: object
      ): Promise<{ name: string; code: string | null; message: string } | null>;
      workerRoundTrip(
        plaintext: number[],
        password: string
      ): Promise<number[]>;
      concurrentRoundTrips(
        payloads: number[][],
        password: string
      ): Promise<number[][]>;
      startCancelableWorker(): Promise<void>;
      waitForCancelableWorker(): Promise<number[]>;
      cancelWorker(): void;
    };
  }
}
