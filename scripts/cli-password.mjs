import { emitKeypressEvents } from "node:readline";
import { createInterface } from "node:readline/promises";

export const CLI_EXIT = Object.freeze({
  OK: 0,
  USAGE: 64,
  PASSWORD: 65,
  INPUT: 66,
  OUTPUT: 73,
  CRYPTO: 74,
});

export class PasswordConfirmationError extends Error {
  constructor() {
    super("Password confirmation does not match");
    this.name = "PasswordConfirmationError";
  }
}

async function readPipedLines(prompts, input, output) {
  const rl = createInterface({ input, output, terminal: false });
  const lines = [];
  try {
    output.write(prompts[0]);
    for await (const line of rl) {
      lines.push(line);
      if (lines.length === prompts.length) break;
      output.write(prompts[lines.length]);
    }
  } finally {
    rl.close();
  }
  if (lines.length !== prompts.length) {
    throw new Error("Password input ended unexpectedly");
  }
  return lines;
}

async function readTtyLine(prompt, input, output) {
  output.write(prompt);
  emitKeypressEvents(input);
  const wasRaw = input.isRaw;
  const wasPaused = input.isPaused();
  input.setRawMode(true);
  input.resume();

  return new Promise((resolve, reject) => {
    let value = "";
    const cleanup = () => {
      input.removeListener("keypress", onKeypress);
      input.setRawMode(Boolean(wasRaw));
      if (wasPaused) input.pause();
    };
    const finish = (result) => {
      output.write("\n");
      cleanup();
      resolve(result);
    };
    const fail = () => {
      output.write("\n");
      cleanup();
      reject(new Error("Password input cancelled"));
    };
    const onKeypress = (text, key) => {
      if (key?.ctrl && (key.name === "c" || key.name === "d")) {
        fail();
      } else if (key?.name === "return" || key?.name === "enter") {
        finish(value);
      } else if (key?.name === "backspace") {
        value = Array.from(value).slice(0, -1).join("");
      } else if (text && !key?.ctrl && !key?.meta) {
        value += text;
      }
    };

    input.on("keypress", onKeypress);
  });
}

export async function readPassword(
  prompt = "Password: ",
  input = process.stdin,
  output = process.stderr
) {
  if (input.isTTY && typeof input.setRawMode === "function") {
    return readTtyLine(prompt, input, output);
  }
  return (await readPipedLines([prompt], input, output))[0];
}

export async function readConfirmedPassword(
  input = process.stdin,
  output = process.stderr
) {
  let password;
  let confirmation;
  if (!input.isTTY || typeof input.setRawMode !== "function") {
    [password, confirmation] = await readPipedLines(
      ["Password: ", "Confirm password: "],
      input,
      output
    );
  } else {
    password = await readPassword("Password: ", input, output);
    confirmation = await readPassword("Confirm password: ", input, output);
  }
  if (password !== confirmation) {
    throw new PasswordConfirmationError();
  }
  return password;
}
