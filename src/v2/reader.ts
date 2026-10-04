import { FormatError, InvalidParamsError } from "../v1/errors";
import {
  decodeDataRecordHeaderV2,
  decodeFinalRecordHeaderV2,
  decodeHeaderV2,
} from "./spec/codec";
import {
  AUTH_TAG_LENGTH_V2,
  MAX_PLAINTEXT_LENGTH_V2,
  RECORD_TYPE_DATA_V2,
  RECORD_TYPE_FINAL_V2,
  V2_DATA_RECORD_HEADER_LENGTH,
  V2_FINAL_RECORD_HEADER_LENGTH,
  V2_HEADER_LENGTH,
} from "./spec/constants";
import type {
  V2DataRecordHeader,
  V2FinalRecordHeader,
  V2Header,
} from "./spec/types";

export type V2HeaderItem = {
  kind: "header";
  bytes: Uint8Array;
  header: V2Header;
};

export type V2DataRecordItem = {
  kind: "data";
  headerBytes: Uint8Array;
  header: V2DataRecordHeader;
  ciphertext: Uint8Array;
  tag: Uint8Array;
};

export type V2FinalRecordItem = {
  kind: "final";
  headerBytes: Uint8Array;
  header: V2FinalRecordHeader;
  tag: Uint8Array;
};

export type V2ReaderItem = V2HeaderItem | V2DataRecordItem | V2FinalRecordItem;
export type V2ReaderItemHandler = (item: V2ReaderItem) => void | Promise<void>;

type ReaderState =
  | "header"
  | "record-type"
  | "data-header"
  | "data-body"
  | "final-record"
  | "done"
  | "failed";

export class V2IncrementalReader {
  private state: ReaderState = "header";
  private pending = new Uint8Array(V2_HEADER_LENGTH);
  private pendingOffset = 0;
  private header: V2Header | undefined;
  private dataHeader: V2DataRecordHeader | undefined;
  private dataHeaderBytes: Uint8Array | undefined;
  private expectedRecordNumber = 0n;
  private totalPlaintextLength = 0n;
  private sawShortDataRecord = false;
  private writing = false;
  private ended = false;
  private _maximumPendingCapacity = V2_HEADER_LENGTH;

  constructor(private readonly emit: V2ReaderItemHandler) {}

  get maximumPendingCapacity(): number {
    return this._maximumPendingCapacity;
  }

  async write(chunk: Uint8Array): Promise<void> {
    if (this.ended) {
      throw new InvalidParamsError("Cannot write after the V2 reader has ended");
    }
    if (this.state === "failed") {
      throw new InvalidParamsError("Cannot reuse a failed V2 reader");
    }
    if (this.writing) {
      throw new InvalidParamsError("Concurrent writes are not supported by the V2 reader");
    }
    if (!(chunk instanceof Uint8Array)) {
      throw new InvalidParamsError("V2 reader input must be a Uint8Array");
    }
    if (chunk.length === 0) return;

    this.writing = true;
    try {
      let sourceOffset = 0;
      while (sourceOffset < chunk.length) {
        if (this.state === "done") {
          throw new FormatError("Unexpected bytes after the V2 FINAL record");
        }

        const remaining = this.pending.length - this.pendingOffset;
        const copied = Math.min(remaining, chunk.length - sourceOffset);
        this.pending.set(chunk.subarray(sourceOffset, sourceOffset + copied), this.pendingOffset);
        this.pendingOffset += copied;
        sourceOffset += copied;

        if (this.pendingOffset === this.pending.length) {
          await this.completePendingItem();
        }
      }
    } catch (error) {
      this.state = "failed";
      throw error;
    } finally {
      this.writing = false;
    }
  }

  end(): void {
    if (this.ended) {
      throw new InvalidParamsError("V2 reader has already ended");
    }
    if (this.writing) {
      throw new InvalidParamsError("Cannot end the V2 reader while a write is active");
    }

    this.ended = true;
    if (this.state === "failed") {
      throw new InvalidParamsError("Cannot finish a failed V2 reader");
    }
    if (this.state !== "done") {
      this.state = "failed";
      throw new FormatError("Unexpected end of CFENC002 archive before FINAL");
    }
  }

  private setPending(length: number, state: ReaderState): void {
    this.pending = new Uint8Array(length);
    this.pendingOffset = 0;
    this.state = state;
    this._maximumPendingCapacity = Math.max(this._maximumPendingCapacity, length);
  }

  private async completePendingItem(): Promise<void> {
    switch (this.state) {
      case "header":
        await this.completeHeader();
        return;
      case "record-type":
        this.completeRecordType();
        return;
      case "data-header":
        this.completeDataHeader();
        return;
      case "data-body":
        await this.completeDataBody();
        return;
      case "final-record":
        await this.completeFinalRecord();
        return;
      case "done":
        throw new FormatError("Unexpected bytes after the V2 FINAL record");
      case "failed":
        throw new InvalidParamsError("Cannot reuse a failed V2 reader");
    }
  }

  private async completeHeader(): Promise<void> {
    const bytes = this.pending;
    const header = decodeHeaderV2(bytes);
    this.header = header;
    await this.emit({ kind: "header", bytes, header });
    this.setPending(1, "record-type");
  }

  private completeRecordType(): void {
    const recordType = this.pending[0]!;
    if (recordType === RECORD_TYPE_DATA_V2) {
      if (this.sawShortDataRecord) {
        throw new FormatError("A V2 DATA record cannot follow a short DATA record");
      }
      this.setPending(V2_DATA_RECORD_HEADER_LENGTH - 1, "data-header");
      return;
    }
    if (recordType === RECORD_TYPE_FINAL_V2) {
      this.setPending(
        V2_FINAL_RECORD_HEADER_LENGTH - 1 + AUTH_TAG_LENGTH_V2,
        "final-record"
      );
      return;
    }
    throw new FormatError(`Unknown V2 record type: ${recordType}`);
  }

  private completeDataHeader(): void {
    const archiveHeader = this.header;
    if (!archiveHeader) {
      throw new FormatError("V2 DATA record encountered before the archive header");
    }

    const headerBytes = new Uint8Array(V2_DATA_RECORD_HEADER_LENGTH);
    headerBytes[0] = RECORD_TYPE_DATA_V2;
    headerBytes.set(this.pending, 1);
    const header = decodeDataRecordHeaderV2(headerBytes, archiveHeader.chunkSize);

    if (header.recordNumber !== this.expectedRecordNumber) {
      throw new FormatError(
        `Unexpected V2 DATA record number: ${header.recordNumber.toString()}`
      );
    }
    const nextTotal = this.totalPlaintextLength + BigInt(header.plaintextLength);
    if (nextTotal > MAX_PLAINTEXT_LENGTH_V2) {
      throw new FormatError("V2 plaintext length exceeds the format limit");
    }

    this.dataHeader = header;
    this.dataHeaderBytes = headerBytes;
    this.setPending(header.plaintextLength + AUTH_TAG_LENGTH_V2, "data-body");
  }

  private async completeDataBody(): Promise<void> {
    const archiveHeader = this.header;
    const header = this.dataHeader;
    const headerBytes = this.dataHeaderBytes;
    if (!archiveHeader || !header || !headerBytes) {
      throw new FormatError("Incomplete V2 DATA parser state");
    }

    const payload = this.pending;
    const ciphertext = payload.subarray(0, header.plaintextLength);
    const tag = payload.subarray(header.plaintextLength);

    this.expectedRecordNumber += 1n;
    this.totalPlaintextLength += BigInt(header.plaintextLength);
    this.sawShortDataRecord = header.plaintextLength < archiveHeader.chunkSize;

    await this.emit({ kind: "data", headerBytes, header, ciphertext, tag });
    this.dataHeader = undefined;
    this.dataHeaderBytes = undefined;
    this.setPending(1, "record-type");
  }

  private async completeFinalRecord(): Promise<void> {
    const headerBytes = new Uint8Array(V2_FINAL_RECORD_HEADER_LENGTH);
    headerBytes[0] = RECORD_TYPE_FINAL_V2;
    headerBytes.set(this.pending.subarray(0, V2_FINAL_RECORD_HEADER_LENGTH - 1), 1);
    const header = decodeFinalRecordHeaderV2(headerBytes);

    if (header.dataRecordCount !== this.expectedRecordNumber) {
      throw new FormatError("V2 FINAL record count does not match DATA records");
    }
    if (header.totalPlaintextLength !== this.totalPlaintextLength) {
      throw new FormatError("V2 FINAL plaintext length does not match DATA records");
    }

    const tag = this.pending.subarray(V2_FINAL_RECORD_HEADER_LENGTH - 1);
    this.state = "done";
    await this.emit({ kind: "final", headerBytes, header, tag });
    this.pending = new Uint8Array(0);
    this.pendingOffset = 0;
  }
}
