export class Writer {
  private chunks: Uint8Array[] = [];
  private _length = 0;

  get length(): number {
    return this._length;
  }

  writeBytes(bytes: Uint8Array) {
    this.chunks.push(bytes);
    this._length += bytes.length;
  }

  writeU8(value: number) {
    this.chunks.push(Uint8Array.of(value & 0xff));
    this._length += 1;
  }

  writeU32BE(value: number) {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value, false);
    this.chunks.push(buf);
    this._length += 4;
  }

  concat(): Uint8Array {
    const total = this.chunks.reduce((s, b) => s + b.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const b of this.chunks) {
      out.set(b, offset);
      offset += b.length;
    }
    return out;
  }

}
