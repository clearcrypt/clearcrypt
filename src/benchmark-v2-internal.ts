// This entry is built for the repository benchmark runner. It is deliberately
// absent from package exports and must not be used as an application API.
export { deriveKekArgon2id } from "./v1/kdf";
export { decryptStreamV2Internal } from "./v2/decrypt-stream";
export { encryptStreamV2Internal } from "./v2/encrypt-stream";
