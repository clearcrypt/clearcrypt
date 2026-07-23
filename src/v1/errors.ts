export class InternalV1Error extends Error {
  readonly cause?: unknown;

  constructor(name: string, message: string, cause?: unknown) {
    super(message);
    this.name = name;
    this.cause = cause;
  }
}

export class InvalidParamsError extends InternalV1Error {
  constructor(message: string, cause?: unknown) {
    super("InvalidParamsError", message, cause);
  }
}

export class FormatError extends InternalV1Error {
  constructor(message: string, cause?: unknown) {
    super("FormatError", message, cause);
  }
}

export class UnsupportedFormatError extends InternalV1Error {
  constructor(message: string, cause?: unknown) {
    super("UnsupportedFormatError", message, cause);
  }
}

export class UnsupportedAlgorithmError extends UnsupportedFormatError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "UnsupportedAlgorithmError";
  }
}

export class ResourcePolicyError extends InternalV1Error {
  constructor(message = "Archive exceeds the local decryption resource policy") {
    super("ResourcePolicyError", message);
  }
}

export class AuthenticationError extends InternalV1Error {
  constructor(cause?: unknown) {
    super("AuthenticationError", "Authentication failed", cause);
  }
}

export class CryptoOperationError extends InternalV1Error {
  constructor(message: string, cause?: unknown) {
    super("CryptoOperationError", message, cause);
  }
}

export class EnvironmentError extends InternalV1Error {
  constructor(message: string, cause?: unknown) {
    super("EnvironmentError", message, cause);
  }
}
