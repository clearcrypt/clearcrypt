import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const FILE_SIZE = 48 * 1024 * 1024;
const MAX_OLD_SPACE_MIB = 32;
const PASSWORD = "v2 streaming CLI test password";
const cliPath = resolve("scripts/cc-file.mjs");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function runCli(command, inputPath, outputPath, passwordInput) {
  const result = spawnSync(
    process.execPath,
    [
      `--max-old-space-size=${MAX_OLD_SPACE_MIB}`,
      cliPath,
      command,
      inputPath,
      outputPath,
    ],
    {
      input: passwordInput,
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      timeout: 120_000,
    }
  );
  if (result.error) throw result.error;
  assert(
    !result.stderr.includes(PASSWORD),
    `${command} exposed the password in stderr`
  );
  return result;
}

async function hashFile(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function expectInterruptedDestinationPreserved(inputPath, outputPath) {
  if (process.platform === "win32") return;

  const sentinel = Buffer.from("existing destination must survive interruption");
  await writeFile(outputPath, sentinel);

  await new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [
        `--max-old-space-size=${MAX_OLD_SPACE_MIB}`,
        cliPath,
        "encrypt-v2",
        inputPath,
        outputPath,
      ],
      { stdio: ["pipe", "pipe", "pipe"] }
    );
    let stderr = "";
    let interrupted = false;
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Interrupted CLI test timed out"));
    }, 120_000);

    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (!interrupted && stderr.includes("Encrypting")) {
        interrupted = true;
        child.kill("SIGINT");
      }
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("close", async (code, signal) => {
      clearTimeout(timeout);
      try {
        assert(interrupted, "CLI did not reach streaming before exiting");
        assert(signal === null, `CLI was terminated by ${signal}`);
        assert(code === 74, `Interrupted CLI returned ${code}, expected 74`);
        assert(stderr.includes("ABORTED"), "Interrupted CLI did not report ABORTED");
        assert(!stderr.includes(PASSWORD), "Interrupted CLI exposed the password");
        assert(
          Buffer.compare(await readFile(outputPath), sentinel) === 0,
          "Interruption replaced the existing destination"
        );
        resolvePromise();
      } catch (error) {
        reject(error);
      }
    });
    child.stdin.end(`${PASSWORD}\n${PASSWORD}\n`);
  });
}

const directory = await mkdtemp(join(tmpdir(), "clearcrypt-cli-v2-"));
try {
  const input = join(directory, "large-input.bin");
  const archive = join(directory, "large-input.cc2");
  const output = join(directory, "large-output.bin");
  const existing = join(directory, "existing-output.bin");
  await writeFile(input, "");
  await truncate(input, FILE_SIZE);

  const encrypted = runCli(
    "encrypt-v2",
    input,
    archive,
    `${PASSWORD}\n${PASSWORD}\n`
  );
  assert(encrypted.status === 0, `Encryption failed:\n${encrypted.stderr}`);
  assert(encrypted.stderr.includes("Encrypting"), "Encryption progress is missing");

  const decrypted = runCli("decrypt-v2", archive, output, `${PASSWORD}\n`);
  assert(decrypted.status === 0, `Decryption failed:\n${decrypted.stderr}`);
  assert(decrypted.stderr.includes("Decrypting"), "Decryption progress is missing");
  assert((await hashFile(output)) === (await hashFile(input)), "Round-trip hash mismatch");

  const sentinel = Buffer.from("existing destination must survive authentication failure");
  await writeFile(existing, sentinel);
  const wrongPassword = runCli("decrypt-v2", archive, existing, "wrong password\n");
  assert(wrongPassword.status === 74, "Wrong password must return exit code 74");
  assert(wrongPassword.stderr.includes("AUTH_FAILED"), "Wrong password error is unclear");
  assert(
    Buffer.compare(await readFile(existing), sentinel) === 0,
    "Authentication failure replaced the existing destination"
  );

  const missingInput = runCli(
    "encrypt-v2",
    join(directory, "missing.bin"),
    join(directory, "unused.cc2"),
    `${PASSWORD}\n${PASSWORD}\n`
  );
  assert(missingInput.status === 66, "Missing input must return exit code 66");

  const missingDirectory = join(directory, "missing-directory");
  const invalidOutput = runCli(
    "encrypt-v2",
    input,
    join(missingDirectory, "unused.cc2"),
    `${PASSWORD}\n${PASSWORD}\n`
  );
  assert(
    invalidOutput.status === 73,
    `Invalid output returned ${invalidOutput.status}, expected 73:\n${invalidOutput.stderr}`
  );

  await mkdir(join(directory, "interrupt"));
  await expectInterruptedDestinationPreserved(
    input,
    join(directory, "interrupt", "existing.cc2")
  );

  console.log(
    `Verified V2 CLI with a ${FILE_SIZE / (1024 * 1024)} MiB file and a ${MAX_OLD_SPACE_MIB} MiB V8 heap limit`
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
