export const MAX_PUBLIC_PASSWORD_BYTES = 1024;

export class PasswordPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PasswordPolicyError";
  }
}

export function passwordToBytes(password: Uint8Array | string): Uint8Array {
  return typeof password === "string"
    ? new TextEncoder().encode(password)
    : password;
}

export function validatePublicPassword(
  password: Uint8Array | string
): Uint8Array {
  if (typeof password === "string") {
    if (password.length === 0) {
      throw new PasswordPolicyError("Password must not be empty");
    }
    // UTF-8 cannot be shorter than the UTF-16 code-unit count. Reject very
    // large strings before allocating their encoded representation.
    if (password.length > MAX_PUBLIC_PASSWORD_BYTES) {
      throw new PasswordPolicyError(
        `Password must not exceed ${MAX_PUBLIC_PASSWORD_BYTES} UTF-8 bytes`
      );
    }
  }
  const bytes = passwordToBytes(password);
  if (bytes.length === 0) {
    throw new PasswordPolicyError("Password must not be empty");
  }
  if (bytes.length > MAX_PUBLIC_PASSWORD_BYTES) {
    throw new PasswordPolicyError(
      `Password must not exceed ${MAX_PUBLIC_PASSWORD_BYTES} UTF-8 bytes`
    );
  }
  return bytes;
}
