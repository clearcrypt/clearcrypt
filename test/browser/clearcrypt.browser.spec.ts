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

test("streams a V2 round-trip in a Web Worker while the page stays responsive", async ({
  page,
}) => {
  const totalBytes = 3 * 64 * 1024 + 17;
  const probe = await page.evaluate(
    ({ totalBytes, password }) =>
      window.clearcryptTest.workerV2RoundTrip(totalBytes, password),
    { totalBytes, password }
  );

  expect(probe.mainThreadTicks).toBeGreaterThan(0);
  expect(probe.value.encryption.inputBytes).toBe(totalBytes);
  expect(probe.value.decryption.outputBytes).toBe(totalBytes);
  expect(probe.value.plaintext.bytes).toBe(totalBytes);
  expect(probe.value.source.checksum).toBe(probe.value.decryptedChecksum);
  expect(probe.value.source.maxChunkBytes).toBeLessThanOrEqual(64 * 1024);
  expect(probe.value.archive.maxActiveWrites).toBe(1);
  expect(probe.value.plaintext.maxActiveWrites).toBe(1);
});

test("decrypts the normative CFENC002 vectors in the browser", async ({ page }) => {
  const results = await page.evaluate(() => window.clearcryptTest.verifyV2Vectors());

  expect(results.map(({ name }) => name)).toEqual([
    "empty-plaintext",
    "unicode-password-binary-plaintext",
    "multiple-blocks-final-short",
  ]);
  for (const result of results) {
    expect(result.plaintextLength).toBe(result.expectedLength);
    expect(result.checksum).toBe(result.expectedChecksum);
  }
});

test("keeps browser V2 stream buffers bounded as simulated input grows", async ({
  page,
}) => {
  const sizes = [1 * 1024 * 1024 + 13, 8 * 1024 * 1024 + 29];
  const probes = [];
  for (const totalBytes of sizes) {
    probes.push(
      await page.evaluate(
        ({ totalBytes, password }) =>
          window.clearcryptTest.workerV2BoundedProbe(totalBytes, password),
        { totalBytes, password }
      )
    );
  }

  for (const [index, probe] of probes.entries()) {
    expect(probe.mainThreadTicks).toBeGreaterThan(0);
    expect(probe.value.result.inputBytes).toBe(sizes[index]);
    expect(probe.value.source.maxChunkBytes).toBeLessThanOrEqual(64 * 1024);
    expect(probe.value.destination.maxWriteBytes).toBeLessThanOrEqual(64 * 1024);
    expect(probe.value.destination.maxActiveWrites).toBe(1);
    expect(probe.value.progressEvents).toBeGreaterThan(0);
  }
  const small = probes[0]!;
  const large = probes[1]!;
  expect(large.value.result.inputBytes).toBeGreaterThan(
    small.value.result.inputBytes * 7
  );
  expect(large.value.source.maxChunkBytes).toBe(
    small.value.source.maxChunkBytes
  );
  expect(large.value.destination.maxWriteBytes).toBe(
    small.value.destination.maxWriteBytes
  );
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

test("cooperatively cancels V2 streams and closes their Worker", async ({ page }) => {
  await page.evaluate(
    ({ password }) =>
      window.clearcryptTest.startCancelableV2Worker(
        32 * 1024 * 1024,
        password
      ),
    { password }
  );
  const pending = page.evaluate(() =>
    window.clearcryptTest.waitForCancelableV2Worker()
  );
  await page.evaluate(() => window.clearcryptTest.cancelV2Worker());

  const result = await pending;
  expect(result.ok).toBe(false);
  expect(result.error.code).toBe("ABORTED");
  expect(result.closing).toBe(true);
  expect(result.diagnostics.source.cancelled).toBe(true);
  expect(result.diagnostics.destination.aborted).toBe(true);
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
      workerV2RoundTrip(
        totalBytes: number,
        password: string
      ): Promise<ResponsiveWorkerResult<V2RoundTripProbe>>;
      workerV2BoundedProbe(
        totalBytes: number,
        password: string
      ): Promise<ResponsiveWorkerResult<V2BoundedProbe>>;
      verifyV2Vectors(): Promise<V2BrowserVectorResult[]>;
      concurrentRoundTrips(
        payloads: number[][],
        password: string
      ): Promise<number[][]>;
      startCancelableWorker(): Promise<void>;
      waitForCancelableWorker(): Promise<number[]>;
      cancelWorker(): void;
      startCancelableV2Worker(totalBytes: number, password: string): Promise<void>;
      waitForCancelableV2Worker(): Promise<V2CancellationResult>;
      cancelV2Worker(): void;
    };
  }
}

type DestinationMetrics = {
  bytes: number;
  writes: number;
  maxActiveWrites: number;
  maxWriteBytes: number;
  aborted: boolean;
};

type SourceMetrics = {
  checksum: number;
  maxChunkBytes: number;
  cancelled: boolean;
};

type OperationMetrics = {
  inputBytes: number;
  outputBytes: number;
  records: number;
};

type ResponsiveWorkerResult<T> = {
  value: T;
  mainThreadTicks: number;
};

type V2RoundTripProbe = {
  source: SourceMetrics;
  archive: DestinationMetrics;
  plaintext: DestinationMetrics;
  decryptedChecksum: number;
  encryption: OperationMetrics;
  decryption: OperationMetrics;
};

type V2BoundedProbe = {
  source: SourceMetrics;
  destination: DestinationMetrics;
  progressEvents: number;
  result: OperationMetrics;
};

type V2CancellationResult = {
  ok: boolean;
  error: { name: string; code: string | null; message: string };
  diagnostics: {
    source: SourceMetrics;
    destination: DestinationMetrics;
  };
  closing: boolean;
};

type V2BrowserVectorResult = {
  name: string;
  plaintextLength: number;
  checksum: number;
  expectedLength: number;
  expectedChecksum: number;
};
