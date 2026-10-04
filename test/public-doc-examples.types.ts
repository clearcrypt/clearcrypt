import { decryptStreamV2, encryptStreamV2 } from "../src/index";
import { decryptFileV2, encryptFileV2 } from "../src/node";

declare const source: ReadableStream<Uint8Array>;
declare const destination: WritableStream<Uint8Array>;
declare const password: string;

const controller = new AbortController();
const encryption = encryptStreamV2(source, destination, password, {
  chunkSize: 4 * 1024 * 1024,
  signal: controller.signal,
  onProgress({ phase, inputBytes, outputBytes, records }) {
    const values: [string, bigint, bigint, bigint] = [
      phase,
      inputBytes,
      outputBytes,
      records,
    ];
    void values;
  },
});

const decryption = decryptStreamV2(source, destination, password, {
  resourcePolicy: {
    maxMemoryCostKiB: 128 * 1024,
    maxTimeCost: 4,
    maxParallelism: 4,
  },
});

const fileEncryption = encryptFileV2("archive.tar", "archive.tar.cc2", password);
const fileDecryption = decryptFileV2(
  "archive.tar.cc2",
  "archive-restauree.tar",
  password
);

type ClearcryptFormat = "CFENC001" | "CFENC002";

function detectClearcryptFormat(prefix: Uint8Array): ClearcryptFormat {
  if (prefix.byteLength < 8) throw new Error("Archive ClearCrypt tronquée");
  const magic = new TextDecoder("ascii", { fatal: true }).decode(
    prefix.subarray(0, 8)
  );
  if (magic === "CFENC001" || magic === "CFENC002") return magic;
  throw new Error("Format ClearCrypt inconnu");
}

void [
  encryption,
  decryption,
  fileEncryption,
  fileDecryption,
  detectClearcryptFormat,
];
