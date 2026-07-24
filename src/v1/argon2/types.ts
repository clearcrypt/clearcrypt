export const ARGON2ID_TYPE = 2;
export const ARGON2_VERSION = 0x13;
export const ARGON2_VERSION_DECIMAL = 19;

export type Argon2idHashParams = {
  password: Uint8Array;
  salt: Uint8Array;
  timeCost: number;
  memoryCostKiB: number;
  parallelism: number;
  hashLengthBytes: number;
};

export type Argon2HashResult = {
  hash: Uint8Array | ArrayBuffer;
  encoded: string;
};

export type Argon2BrowserModule = {
  ArgonType: {
    Argon2id: number;
  };
  hash(params: {
    pass: Uint8Array;
    salt: Uint8Array;
    time: number;
    mem: number;
    parallelism: number;
    hashLen: number;
    type: number;
  }): Promise<Argon2HashResult>;
};

export function normalizeArgon2Module(value: unknown): Argon2BrowserModule {
  const imported = value as {
    default?: unknown;
    ArgonType?: { Argon2id?: unknown };
    hash?: unknown;
  };
  const candidate = (imported.default ?? imported) as {
    ArgonType?: { Argon2id?: unknown };
    hash?: unknown;
  };

  if (
    typeof candidate.hash !== "function" ||
    candidate.ArgonType?.Argon2id !== ARGON2ID_TYPE
  ) {
    throw new Error("argon2-browser does not expose the expected Argon2id API");
  }

  return candidate as Argon2BrowserModule;
}

export function toArgon2BrowserParams(params: Argon2idHashParams) {
  return {
    pass: params.password,
    salt: params.salt,
    time: params.timeCost,
    mem: params.memoryCostKiB,
    parallelism: params.parallelism,
    hashLen: params.hashLengthBytes,
    type: ARGON2ID_TYPE,
  };
}
