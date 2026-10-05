import { randomUUID } from "node:crypto";
import { closeSync, openSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

// Use a trusted destination directory. Exclusive creation avoids following a
// pre-existing symlink; rename publishes only a completely written private file.
export function writePrivateFileAtomic(outputPath, bytes) {
  const target = resolve(outputPath);
  const temporary = join(
    dirname(target),
    `.${basename(target)}.clearcrypt-${process.pid}-${randomUUID()}.tmp`
  );
  let descriptor;
  let ownsTemporaryFile = false;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    ownsTemporaryFile = true;
    writeFileSync(descriptor, bytes);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, target);
    ownsTemporaryFile = false;
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* Preserve the original failure. */ }
    }
    if (ownsTemporaryFile) {
      try { unlinkSync(temporary); } catch { /* Preserve the original failure. */ }
    }
  }
}
