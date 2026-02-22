const globalAny = globalThis as {
  self?: unknown;
  process?: NodeJS.Process;
};

if (!globalAny.self) {
  globalAny.self = globalThis;
}

if (!globalAny.process) {
  globalAny.process = process;
}
