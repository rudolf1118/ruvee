# Argon2id calibration (P2-02, local part)

Status: **Proposed. Measurement only.** This report records how long the candidate library takes
to run Argon2id on **one computer**. It approves nothing: profile 1 stays provisional (D-03), the
reference devices are not chosen (D-26 is open), and no production parameter is final. These
results say nothing about phones or older laptops, and must not be used to argue for them.

Date: 2026-10-23. Tooling:
[`tools/crypto-validation/src/calibration/`](../../tools/crypto-validation/README.md#argon2id-calibration-benchmark-p2-02).
All inputs are synthetic.

## 1. What was measured

`crypto_pwhash(32, password, salt, opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13)` from
`libsodium-wrappers-sumo` 0.8.4 with `libsodium-sumo` 0.8.4 (libsodium 1.0.22), exactly the
versions pinned for P2-01. That call is Argon2id version 0x13 with t = `opslimit`,
m = `memlimit` / 1024 KiB and p = 1, a 16-byte salt, a 24-byte password, a 32-byte output, and no
secret or associated data. Each run confirmed this mapping with libsodium's own encoded string,
and every environment produced the same output for each configuration.

| Id           | Memory  | t   | Role                                            | Basis in the specification                                                                                     |
| ------------ | ------- | --- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `ref-19m-t2` | 19 MiB  | 2   | Comparison only; weaker than profile 1          | OWASP server-side minimum, cited in [research-sources.md](research-sources.md)                                 |
| `p1-64m-t3`  | 64 MiB  | 3   | **Baseline: profile 1** (provisional)           | [cryptographic-design.md §3.2](cryptographic-design.md#32-argon2id-profiles); RFC 9106's second recommendation |
| `c-64m-t4`   | 64 MiB  | 4   | Candidate: stronger in time, same memory        | Stays inside §3.2's 128 MiB peak-memory budget; profile 1 may only be strengthened                             |
| `c-128m-t3`  | 128 MiB | 3   | Candidate: stronger in memory, up to the budget | §3.2's 128 MiB peak-memory budget                                                                              |
| `p2-256m-t3` | 256 MiB | 3   | Reserved profile 2                              | §3.2; above the peak-memory budget by design                                                                   |

Method:

- One dedicated worker at a time (`worker_threads` in Node, a Web Worker in browsers). A fresh
  worker per configuration, terminated afterwards. Engines and configurations run one after
  another, never in parallel.
- Order: the five configurations by increasing cost, then profile 1 again to expose drift.
- Per configuration: 3 warm-up derivations (discarded), then 20 timed derivations. Only the
  `crypto_pwhash` call is timed, inside the worker. p95 is the nearest-rank value (the 19th of 20).
- Worker initialisation is measured separately: 10 workers in a row, from creation to "libsodium
  ready".
- Two complete runs (A at 10:29 UTC and B at 10:32 UTC), each in Node and four browsers.

## 2. Environment

| Item                    | Value                                                                                                                                                                                                       |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Computer                | Apple Mac17,2, Apple M5 (4 performance and 6 efficiency cores), 16 GiB                                                                                                                                      |
| Operating system        | macOS 26.5.1 (25F80), Darwin 25.5.0, arm64                                                                                                                                                                  |
| Power and thermal state | On battery (about 88%), Low Power Mode off, no thermal or performance warning recorded by `pmset`                                                                                                           |
| Load                    | 1-minute load average 5.6 to 11.0 during the runs; about 180 MB free memory at the start. Other workloads (a Docker VM, an Android emulator and desktop applications) were running and were left untouched. |
| Node                    | 24.13.0 (V8 13.6), `worker_threads`                                                                                                                                                                         |
| Playwright Chromium     | 156.0.8078.4, headless shell (Playwright 1.64.1 build)                                                                                                                                                      |
| Google Chrome           | 155.0.8059.85, installed release, headless, launched by Playwright with a temporary profile                                                                                                                 |
| Playwright Firefox      | 157.0, Playwright's patched build, **not stock Firefox**                                                                                                                                                    |
| Playwright WebKit       | 27.2, Playwright's WebKit build, **not Safari** (its user-agent string nevertheless says "Safari")                                                                                                          |
| Page                    | Served on 127.0.0.1 with a CSP that adds only `'wasm-unsafe-eval'`, cross-origin isolated (worker timer resolution 5 µs in Chromium and Chrome, 20 µs in Firefox and WebKit)                                |

The machine was **not idle and not plugged in**. The numbers are therefore realistic for a busy
desktop on battery, not best-case figures, and they vary between runs.

## 3. Results

Median (p95) in milliseconds. 20 samples each, **no failures** in any run.

| Environment         | Run | `ref-19m-t2` | **`p1-64m-t3`**  | `c-64m-t4`    | `c-128m-t3`   | `p2-256m-t3`  | `p1-64m-t3` again |
| ------------------- | --- | ------------ | ---------------- | ------------- | ------------- | ------------- | ----------------- |
| Node 24.13.0        | A   | 19.1 (25.8)  | **93.2 (139.4)** | 125.6 (193.3) | 198.1 (270.1) | 427.4 (499.0) | 94.5 (113.2)      |
| Node 24.13.0        | B   | 16.9 (47.6)  | **90.6 (161.7)** | 113.9 (120.4) | 179.5 (300.0) | 368.2 (416.6) | 87.9 (96.7)       |
| Playwright Chromium | A   | 15.7 (19.5)  | **84.7 (88.3)**  | 112.1 (142.2) | 176.0 (255.2) | 378.7 (407.6) | 86.1 (92.6)       |
| Playwright Chromium | B   | 14.7 (16.6)  | **81.9 (85.6)**  | 115.9 (195.8) | 178.7 (207.8) | 380.3 (433.6) | 86.6 (97.1)       |
| Google Chrome       | A   | 16.9 (22.6)  | **87.3 (99.0)**  | 117.4 (148.8) | 186.2 (220.5) | 373.9 (450.4) | 86.2 (89.9)       |
| Google Chrome       | B   | 23.6 (32.4)  | **96.9 (133.3)** | 108.7 (114.9) | 175.4 (185.0) | 398.2 (617.7) | 91.6 (119.9)      |
| Playwright Firefox  | A   | 21.9 (39.4)  | **98.0 (124.0)** | 134.7 (210.6) | 195.0 (254.3) | 408.9 (596.4) | 89.9 (147.0)      |
| Playwright Firefox  | B   | 15.8 (19.8)  | **97.8 (348.8)** | 120.6 (129.7) | 231.3 (335.9) | 453.5 (693.4) | 90.5 (110.3)      |
| Playwright WebKit   | A   | 15.7 (21.2)  | **88.3 (116.4)** | 113.8 (127.5) | 171.2 (180.6) | 396.4 (431.0) | 87.6 (119.3)      |
| Playwright WebKit   | B   | 15.3 (16.2)  | **86.0 (89.1)**  | 112.7 (116.7) | 172.3 (227.8) | 387.8 (524.3) | 88.7 (101.3)      |

What these numbers show, on this machine only:

- **Profile 1:** median 82 to 98 ms in every engine and in Node. p95 is at most 162 ms except one
  run (Firefox B, 349 ms), where nine consecutive samples ran slow (112 to 420 ms). That is
  likely other load on this busy machine, but load was not recorded per browser run. The repeat at the end of each run
  (86 to 95 ms) shows no drift.
- **Relative cost** (ratio of medians within the same run): one more iteration (`c-64m-t4`) adds
  12 to 42%, typically about 30%; doubling the memory (`c-128m-t3`) costs 1.8 to 2.4 times
  profile 1; profile 2 costs 4.1 to 4.6 times.
- Engines differ by about as much as runs do. Firefox was the slowest by a few percent.
- The architecture spike on 2026-10-22 measured 78 to 100 ms for profile 1 on the same machine.
  Today's medians are within about 15% of those, with today's heavier load and battery power.

### Worker initialisation

Milliseconds from creating the worker to "libsodium ready", split into loading and evaluating
the script and initialising libsodium.

| Environment         | First worker, run A (load + libsodium) | First worker, run B | Next 9 workers: median (min–max), run A / run B |
| ------------------- | -------------------------------------- | ------------------- | ----------------------------------------------- |
| Node 24.13.0        | 43.6 (39.6 + 4.0)                      | 39.0 (35.0 + 4.1)   | 21.4 (20.9–25.9) / 23.3 (21.2–24.3)             |
| Playwright Chromium | 255.4 (247.2 + 8.2)                    | 21.9 (14.9 + 7.1)   | 12.8 (11.8–16.9) / 10.9 (10.3–13.8)             |
| Google Chrome       | 21.2 (16.5 + 4.7)                      | 52.0 (34.4 + 17.6)  | 12.9 (12.0–20.8) / 16.0 (12.8–37.8)             |
| Playwright Firefox  | 20.3 (14.1 + 6.2)                      | 84.2 (53.4 + 30.9)  | 29.1 (18.6–145.4) / 23.4 (15.4–74.3)            |
| Playwright WebKit   | 11.8 (7.5 + 4.4)                       | 40.0 (29.0 + 11.0)  | 8.1 (7.6–25.2) / 8.1 (7.5–9.9)                  |

Initialisation is small next to one derivation here. The 255 ms first worker in Chromium run A
was the only cold start that large; its cause (likely first compilation without a cache) was not
investigated. Loading includes fetching the 580 KiB worker script from 127.0.0.1 with caching
disabled.

### Cancellation and worker cleanup

Passed in all 10 runs.

| Behavior                                         | Browsers                                           | Node                                             |
| ------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------ |
| Cooperative cancel (checked between derivations) | Stopped after 83 to 89 ms, about one derivation    | Stopped after 1.5 to 3.1 ms                      |
| `terminate()` during a 256 MiB derivation        | Returns at once (≤ 0.07 ms); no message afterwards | Resolves in 3.6 to 4.1 ms; no message afterwards |
| A new worker afterwards                          | Initialises and runs normally                      | Initialises and runs normally                    |

A derivation cannot be interrupted from inside the worker. Cooperative cancel waits for the
derivation in progress (up to one derivation, about 90 ms here). Only `terminate()` stops one
immediately, and it discards the worker with its WebAssembly memory. A production design must
therefore terminate the crypto worker to cancel an unlock, and create a new one afterwards.

### Memory

Only what can be measured honestly is reported:

| Configuration | Node: whole-process peak RSS (idle process 45 MiB) | Browsers: WebAssembly linear memory after the run (all engines) |
| ------------- | -------------------------------------------------- | --------------------------------------------------------------- |
| `ref-19m-t2`  | 92 MiB                                             | 19.2 MiB                                                        |
| `p1-64m-t3`   | 136 to 137 MiB                                     | 64.3 MiB                                                        |
| `c-64m-t4`    | 137 MiB                                            | 64.3 MiB                                                        |
| `c-128m-t3`   | 200 to 201 MiB                                     | 128.4 MiB                                                       |
| `p2-256m-t3`  | 319 to 329 MiB                                     | 256.6 MiB                                                       |

- The Node figure is the peak resident set size of the whole Node process (`getrusage`), one
  process per configuration, including the runtime, the worker thread and the copy of libsodium.
- The browser figure is the size of libsodium's WebAssembly memory: the Argon2 memory plus about
  0.25 to 0.6 MiB of libsodium's own heap. It is **not total peak memory**. The worker's
  JavaScript heap, the compiled module and the browser process are not included, and total peak
  memory was not measured in any browser.

## 4. V-15 in the benchmark

V-15 is the libsodium.js 0.8.4 defect where `crypto_kdf_derive_from_key` returns uninitialised
memory for subkey lengths outside 16..64
([architecture-validation.md §1](architecture-validation.md#1-findings)).

- The benchmark derives one 32-byte subkey per configuration (timed separately: 0.1 to 0.4 ms). Before that call, its own guard requires a subkey length of exactly 32, a 32-byte key,
  an 8-character printable-ASCII context and an id up to 2³¹ − 1. The benchmark never calls the
  affected function with an invalid length.
- `crypto_pwhash` is guarded too: only registry configurations, whole-KiB memory at most 256 MiB,
  a 32-byte output and a 16-byte salt, because libsodium rounds and accepts silently.
- The self-test, which runs in CI, checks that every invalid argument is rejected with no library
  call. With the guard deliberately loosened to libsodium's documented range (16 to 64), it fails.
- **This is the benchmark's own check, not a fix.** V-15 remains an open production integration
  issue: upstream fixed it on master (`86ea6ed`) but has not released it, and the dependency
  versions were not changed. `packages/crypto` (P2-03) must apply the same rule.

## 5. Limitations

- **One computer**, a 2026 Apple M5 laptop, busy and on battery. Nothing here predicts phones,
  older laptops or low-end devices. Relative costs between configurations may differ on other
  hardware.
- **Safari was not measured.** Playwright WebKit is not Safari, and Safari automation was not
  enabled (that needs an OS setting). The manual page covers it.
- **No phones, no older laptops, no React Native**, and no MV3 extension service worker (the
  architecture spike measured it 3.7 times slower than a page worker; Phase 5).
- **Headless browsers** only. The spike found no headless effect on page workers, but this was
  not re-checked.
- **Total peak memory in browsers is unknown.** The WebAssembly memory size is a lower bound for
  what the derivation needs, not the process peak.
- **Only `crypto_pwhash`.** A login also runs the OPAQUE key-stretching function inside
  `@serenity-kit/opaque` (Argon2id, 64 MiB, t = 3, p = 4), which the architecture spike measured
  at about 92 to 100 ms here. It is not part of this benchmark, so a login-and-unlock costs more
  than the figures above.
- Short runs (about 25 seconds per engine) do not show sustained thermal throttling, which matters
  on phones.

## 6. Provisional recommendation

**Keep profile 1 at 64 MiB, t = 3, p = 1, unchanged and provisional.** Nothing measured here
justifies finalizing, raising or lowering it. Reasons:

1. **The time budget has a large margin on this machine only.** The budget in §3.2 is a median of
   at most 2 seconds on the reference low-end device. Here profile 1 takes about 90 ms, so the
   margin is about 20 times. The reference devices could be far slower; that is unmeasured, and
   no factor is assumed.
2. **More memory does not fit the memory budget.** `c-128m-t3` needs 128 MiB for the Argon2
   memory alone, which uses the whole 128 MiB peak budget before anything else is counted, and
   profile 2 is double that. Neither can meet the budget as written.
3. **More time is the only strengthening that fits**, and it should wait. `c-64m-t4` costs 12 to
   42% more than profile 1 at the same memory (typically about 30%). Whether to adopt it depends on the reference-device
   medians, which do not exist yet.
4. **The memory budget needs a definition before it can be checked.** In Node, profile 1's
   whole-process peak (136 to 137 MiB) already exceeds 128 MiB, mostly because the idle runtime
   is 45 MiB, while the derivation's own memory is 64.3 MiB. A browser tab and its worker have a
   larger baseline still. The owner should state whether "peak 128 MiB" means memory attributable
   to the derivation, or the whole worker or tab, and how it is measured on phones (for example
   Android's per-process memory report, or Safari's Web Inspector timelines). This is part of
   D-03.
5. **Profile 2 stays reserved.** It costs 4.1 to 4.6 times profile 1 and exceeds the memory
   budget by design.
6. **Operational findings for P2-03 and P2-10**, provisional: run derivations in a dedicated
   worker; cancel an unlock by terminating that worker; expect initialisation of 10 to 30 ms after
   the first worker (up to 255 ms for a cold first worker here); never pass parameters that are
   not in the profile registry; guard `crypto_kdf_derive_from_key` lengths (V-15).

## 7. What remains

- **D-26 (open):** the owner names the reference devices: the oldest laptop browser and the phones
  Ruvee should support.
- **P2-02, reference devices:** run the [manual page](../../tools/crypto-validation/README.md#manual-runs-safari-and-other-devices)
  on those devices and on Safari, twice each, and add the results here. Then D-03 can be decided,
  with a definition of the memory budget.
- Measuring the OPAQUE key-stretching function on the same devices belongs with P2-08 or P2-09,
  which add `@serenity-kit/opaque`.

## Results files

The raw JSON is written to `tools/crypto-validation/results/calibration/` (ignored by git) and
can be regenerated with the commands in the tool README. Tables in this report were produced with
`node src/calibration/summarize.mjs` from runs A and B.
