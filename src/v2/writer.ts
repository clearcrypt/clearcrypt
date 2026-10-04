import { FormatError, InvalidParamsError } from "../v1/errors";
import {
  encodeDataRecordHeaderV2,
  encodeFinalRecordHeaderV2,
  encodeHeaderV2,
} from "./spec/codec";
import {
  AUTH_TAG_LENGTH_V2,
  MAX_PLAINTEXT_LENGTH_V2,
} from "./spec/constants";
import type {
  V2DataRecordHeader,
  V2FinalRecordHeader,
  V2Header,
} from "./spec/types";

export interface V2ByteDestination {
  write(chunk: Uint8Array): void | Promise<void>;
}

type WriterState = "initial" | "data" | "done" | "failed";

export class V2IncrementalWriter {
  private state: WriterState = "initial";
  private chunkSize: number | undefined;
  private expectedRecordNumber = 0n;
  private totalPlaintextLength = 0n;
  private sawShortDataRecord = false;
  private writing = false;

  constructor(private readonly destination: V2ByteDestination) {
    if (!destination || typeof destination.write !== "function") {
      throw new InvalidParamsError("V2 writer destination must provide write(chunk)");
    }
  }

  async writeHeader(header: V2Header): Promise<void> {
    this.beginWrite("initial", "V2 header has already been written");
    try {
      const bytes = encodeHeaderV2(header);
      await this.destination.write(bytes);
      this.chunkSize = header.chunkSize;
      this.state = "data";
    } catch (error) {
      this.state = "failed";
      throw error;
    } finally {
      this.writing = false;
    }
  }

  async writeDataRecord(
    header: V2DataRecordHeader,
    ciphertext: Uint8Array,
    tag: Uint8Array
  ): Promise<void> {
    this.beginWrite("data", "V2 DATA records require a header and cannot follow FINAL");
    try {
      const chunkSize = this.chunkSize;
      if (chunkSize === undefined) {
        throw new FormatError("V2 writer is missing the archive chunk size");
      }
      if (!(ciphertext instanceof Uint8Array)) {
        throw new InvalidParamsError("V2 DATA ciphertext must be a Uint8Array");
      }
      this.requireTag(tag, "DATA");
      if (header.recordNumber !== this.expectedRecordNumber) {
        throw new InvalidParamsError(
          `Unexpected V2 DATA record number: ${header.recordNumber.toString()}`
        );
      }
      if (header.plaintextLength !== ciphertext.length) {
        throw new InvalidParamsError(
          "V2 DATA plaintext length must equal the ciphertext length"
        );
      }
      if (this.sawShortDataRecord) {
        throw new InvalidParamsError("A V2 DATA record cannot follow a short DATA record");
      }

      const headerBytes = encodeDataRecordHeaderV2(header, chunkSize);
      const nextTotal = this.totalPlaintextLength + BigInt(header.plaintextLength);
      if (nextTotal > MAX_PLAINTEXT_LENGTH_V2) {
        throw new InvalidParamsError("V2 plaintext length exceeds the format limit");
      }

      await this.destination.write(headerBytes);
      await this.destination.write(ciphertext);
      await this.destination.write(tag);

      this.expectedRecordNumber += 1n;
      this.totalPlaintextLength = nextTotal;
      this.sawShortDataRecord = header.plaintextLength < chunkSize;
    } catch (error) {
      this.state = "failed";
      throw error;
    } finally {
      this.writing = false;
    }
  }

  async writeFinalRecord(header: V2FinalRecordHeader, tag: Uint8Array): Promise<void> {
    this.beginWrite("data", "V2 FINAL requires a header and can only be written once");
    try {
      this.requireTag(tag, "FINAL");
      if (header.dataRecordCount !== this.expectedRecordNumber) {
        throw new InvalidParamsError("V2 FINAL record count does not match DATA records");
      }
      if (header.totalPlaintextLength !== this.totalPlaintextLength) {
        throw new InvalidParamsError(
          "V2 FINAL plaintext length does not match DATA records"
        );
      }

      await this.destination.write(encodeFinalRecordHeaderV2(header));
      await this.destination.write(tag);
      this.state = "done";
    } catch (error) {
      this.state = "failed";
      throw error;
    } finally {
      this.writing = false;
    }
  }

  private beginWrite(requiredState: WriterState, message: string): void {
    if (this.writing) {
      throw new InvalidParamsError("Concurrent writes are not supported by the V2 writer");
    }
    if (this.state === "failed") {
      throw new InvalidParamsError("Cannot reuse a failed V2 writer");
    }
    if (this.state !== requiredState) {
      throw new InvalidParamsError(message);
    }
    this.writing = true;
  }

  private requireTag(tag: Uint8Array, recordName: string): void {
    if (!(tag instanceof Uint8Array) || tag.length !== AUTH_TAG_LENGTH_V2) {
      throw new InvalidParamsError(
        `V2 ${recordName} tag must be exactly ${AUTH_TAG_LENGTH_V2} bytes`
      );
    }
  }
}

export class V2BoundedMemoryDestination implements V2ByteDestination {
  private readonly chunks: Uint8Array[] = [];
  private length = 0;

  constructor(readonly maximumBytes: number) {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
      throw new InvalidParamsError("V2 memory destination limit must be a non-negative safe integer");
    }
  }

  get bytesWritten(): number {
    return this.length;
  }

  write(chunk: Uint8Array): void {
    if (!(chunk instanceof Uint8Array)) {
      throw new InvalidParamsError("V2 destination input must be a Uint8Array");
    }
    if (chunk.length > this.maximumBytes - this.length) {
      throw new InvalidParamsError("V2 memory destination byte limit exceeded");
    }
    this.chunks.push(chunk.slice());
    this.length += chunk.length;
  }

  toUint8Array(): Uint8Array {
    const result = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
}

export class V2CountingDestination implements V2ByteDestination {
  bytesWritten = 0n;
  writes = 0n;

  write(chunk: Uint8Array): void {
    if (!(chunk instanceof Uint8Array)) {
      throw new InvalidParamsError("V2 destination input must be a Uint8Array");
    }
    this.bytesWritten += BigInt(chunk.length);
    this.writes += 1n;
  }
}
