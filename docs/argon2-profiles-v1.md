# Argon2id profiles and benchmark protocol

ClearCrypt V1 exposes named, versioned Argon2id profiles. A profile identifier
is immutable: changing any Argon2 parameter requires a new identifier.

| Profile | Memory | Passes | Parallelism |
| --- | ---: | ---: | ---: |
| `interactive-v1` | 64 MiB | 2 | 2 |
| `hardened-v1` | 128 MiB | 3 | 2 |

`interactive-v1` is the default. The former names `interactive` and `hardened`
remain aliases for compatibility and resolve respectively to the two versioned
profiles above. Explicit `kdf` values still override a selected profile.

These profiles do not weaken themselves according to the device. If a device
cannot run a profile within its resource limits, the operation fails instead of
silently reducing its security.

## Node.js benchmark

Build the package, then run:

```sh
npm run build
npm run benchmark:argon2:v1
```

The runner executes every profile in a fresh child process and reports JSON. It
uses an empty plaintext so the result predominantly measures the KDF and its
runtime. Each profile includes:

- cold derivation duration;
- warm sample durations, median, p95, minimum, and maximum;
- two concurrent encryptions, which exercise the serialized WASM runtime;
- baseline and final RSS, maximum RSS delta, and `arrayBuffers` delta;
- Node.js, OS, CPU, logical CPU count, and physical-memory information.

The defaults are one warm-up and five measured runs. For a specific profile or
a longer sample:

```sh
npm run benchmark:argon2:v1 -- --profile interactive-v1 --runs 20 --warmups 2
```

Do not compare results produced under unrelated system load. Keep the machine
on AC power where applicable, close heavy applications, record thermal and
power-saving conditions, and retain the emitted JSON with the test report.
Performance thresholds are intentionally not enforced in CI because hosted
runners do not provide stable timing or memory baselines.

### Development workstation reference

This is a local sanity check, not a substitute for the device matrix below.
It was recorded on Node.js 24.18.0, Windows 10.0.19045, an Intel Core
i5-11600K (12 logical CPUs), and about 32 GiB of RAM, with five measured runs:

| Profile | Cold | Warm median | Warm p95 | Concurrent pair | Max RSS delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| `interactive-v1` | 210.9 ms | 172.0 ms | 180.0 ms | 340.2 ms | 69.3 MiB |
| `hardened-v1` | 579.8 ms | 524.8 ms | 535.6 ms | 1047.1 ms | 133.6 MiB |

## Browser and Web Worker benchmark

Build and start the local harness:

```sh
npm run build
npm run benchmark:argon2:browser
```

Open the printed localhost URL on the test browser. The harness bundles the same
public browser entry point shipped by the npm package. It can run each profile:

- on the main thread;
- in a Web Worker;
- in both modes for a direct comparison.

It reports cold and warm durations, median, p95, min/max, total wall time,
the largest `requestAnimationFrame` gap as a proxy for visible UI blocking,
and browser memory when an appropriate browser API is available. Download the
JSON result and attach it to the benchmark report.

Web Crypto requires a secure context. For a phone or another LAN device, use a
certificate trusted by that device and start the server with HTTPS:

```sh
npm run benchmark:argon2:browser -- --cert path/to/cert.pem --key path/to/key.pem
```

The certificate must cover the hostname or IP address used by the device.
Do not bypass certificate warnings for benchmark runs; a plain LAN HTTP URL is
not an equivalent test environment.

Browser memory APIs are not consistently available. A `null` value means the
browser did not expose a usable measurement; do not replace it with an
estimate. Web Workers protect the main UI thread but do not make Argon2 itself
cheaper. ClearCrypt also serializes concurrent Argon2 jobs because
`argon2-browser` uses shared mutable WASM runtime state.

## Required device matrix

Run both profiles in both main-thread and Worker modes for every row:

| Device class | Browsers |
| --- | --- |
| Entry-level PC | Current Chrome and Firefox |
| Current development PC | Current Chrome and Firefox |
| Midrange Android phone | Current Chrome |
| Supported iPhone | Current Safari |
| macOS device | Current Safari/WebKit |

For every run, retain the JSON plus the exact device model, OS/browser version,
power mode, and whether the device was thermally constrained. Review profile
parameters only from the complete matrix. Any later tuning must introduce a new
profile name such as `interactive-v2`; it must never change the meaning of an
existing profile or an encrypted archive.
