export class Reader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {}

  readBytes(length: number): Uint8Array {
    if (this.offset + length > this.data.length) {
      throw new Error("Unexpected end of file");
    }
    const slice = this.data.slice(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  readU8(): number {
    return this.readBytes(1)[0]!;
  }

  readU32BE(): number {
    const buf = this.readBytes(4);
    return new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, false);
  }

  remaining(): Uint8Array {
    return this.data.slice(this.offset);
  }
}