# Evidence: request overhead of the shared limits (2026-10-30)

Recovered for the deployment rehearsal report from the measurement retained in the development
session (raw output and the spec that produced it, both reproduced below unchanged). Quoted in
[followup-review.md §18.7](../followup-review.md). **Local measurements on one laptop; not a
capacity figure.**

## Result

Median of the per-round p50 latencies, in milliseconds:

| Request                           | `c74f922` (before) | Shared limits (after) | Rounds (before / after) |
| --------------------------------- | ------------------ | --------------------- | ----------------------- |
| Authenticated `GET /account/keys` | 1.34 ms            | 2.37 ms               | 9 / 9                   |
| `login/start`                     | 2.26 ms            | 5.07 ms               | 9 / 9                   |
| `login/finish`                    | 5.39 ms            | 7.15 ms               | 9 / 9                   |

## Method

- **What ran:** `measure-17-2.int-spec.ts` (below), a throwaway Vitest spec using the API's own
  integration harness: one Nest application in the test process, requests through supertest
  over loopback HTTP, one synthetic account, with the API connected as the runtime role to a
  task-owned PostgreSQL 18 container (Docker Desktop, macOS arm64).
- **Per round:** 280 sequential authenticated `GET /api/v1/account/keys`, the first 20 discarded
  (260 kept); 31 sequential logins (`login/start` then `login/finish` with a device proof), the
  first discarded (30 kept). The per-address windows are cleared before each block, so no
  request is refused.
- **Per run:** three rounds. **Interleaving:** three runs per build, alternating builds
  (before, after, before, after, …), so drift on the laptop affects both.
- **Builds:** "before" is the `ruvee-f19` worktree at `c74f922` (in-memory limits and login
  states); "after" is the `ruvee-limits` worktree with the shared limits, the ADR-0002 login-state
  seal and the uncached maintenance gate.

## Limitations

- **Which code was measured.** The output file was written at 10:07 local time on 2026-10-30
  from the `ruvee-limits` working tree; commits `1c9fe82`…`87497e4` were made from that tree at
  10:18. The working tree at 10:07 was not recorded, so this evidence does not prove that the
  measured code is byte-identical to `87497e4`. The measurement was not repeated on the commit:
  the local Docker daemon stopped responding on the day of the rehearsal preparation, and the
  host rehearsal measures resources, not latency.
- One laptop, shared with other work and other projects' containers; no repetition on another
  machine. Sequential requests from one client: no concurrency, no contention, no Caddy, TLS or
  network. The numbers compare two builds under the same conditions; they do not predict a VPS.
- The "after" build adds several things at once (shared windows, the database-held login state,
  the seal, reading the gate on every request); the measurement does not separate them.

## Raw output (`measure-final.txt`, SHA-256 `b6dd1edbe01d968c039d5871324b63b318c221da9e9dff61b3f72ba2b950577f`)

```text
== ruvee-f19 run 1
round 0 GET /account/keys n=260 p50=1.37ms p95=1.78ms mean=1.42ms
round 0 login/start n=30 p50=2.20ms p95=3.95ms mean=2.46ms
round 0 login/finish n=30 p50=5.11ms p95=7.15ms mean=5.32ms
round 1 GET /account/keys n=260 p50=1.32ms p95=2.47ms mean=1.52ms
round 1 login/start n=30 p50=2.18ms p95=2.96ms mean=2.25ms
round 1 login/finish n=30 p50=5.29ms p95=8.80ms mean=5.79ms
round 2 GET /account/keys n=260 p50=1.29ms p95=3.86ms mean=1.71ms
round 2 login/start n=30 p50=2.22ms p95=3.71ms mean=2.41ms
round 2 login/finish n=30 p50=5.07ms p95=8.84ms mean=6.11ms
exit 0
== ruvee-limits run 1
round 0 GET /account/keys n=260 p50=2.56ms p95=6.13ms mean=3.12ms
round 0 login/start n=30 p50=5.20ms p95=12.10ms mean=6.13ms
round 0 login/finish n=30 p50=7.37ms p95=13.94ms mean=7.91ms
round 1 GET /account/keys n=260 p50=2.28ms p95=3.13ms mean=2.38ms
round 1 login/start n=30 p50=5.07ms p95=20.18ms mean=6.67ms
round 1 login/finish n=30 p50=6.97ms p95=10.79ms mean=8.17ms
round 2 GET /account/keys n=260 p50=2.37ms p95=4.08ms mean=2.64ms
round 2 login/start n=30 p50=4.95ms p95=7.93ms mean=5.50ms
round 2 login/finish n=30 p50=6.49ms p95=13.73ms mean=8.28ms
exit 0
== ruvee-f19 run 2
round 0 GET /account/keys n=260 p50=1.34ms p95=2.03ms mean=1.43ms
round 0 login/start n=30 p50=2.48ms p95=3.52ms mean=2.93ms
round 0 login/finish n=30 p50=9.80ms p95=12.26ms mean=9.38ms
round 1 GET /account/keys n=260 p50=1.39ms p95=2.07ms mean=1.49ms
round 1 login/start n=30 p50=2.27ms p95=3.59ms mean=2.38ms
round 1 login/finish n=30 p50=5.45ms p95=8.16ms mean=5.94ms
round 2 GET /account/keys n=260 p50=1.23ms p95=1.73ms mean=1.34ms
round 2 login/start n=30 p50=2.31ms p95=4.99ms mean=2.55ms
round 2 login/finish n=30 p50=5.17ms p95=13.11ms mean=6.77ms
exit 0
== ruvee-limits run 2
round 0 GET /account/keys n=260 p50=2.43ms p95=3.77ms mean=2.59ms
round 0 login/start n=30 p50=6.53ms p95=10.46ms mean=6.86ms
round 0 login/finish n=30 p50=12.54ms p95=14.97ms mean=12.37ms
round 1 GET /account/keys n=260 p50=2.36ms p95=4.78ms mean=2.79ms
round 1 login/start n=30 p50=5.83ms p95=7.87ms mean=5.82ms
round 1 login/finish n=30 p50=8.02ms p95=11.92ms mean=8.52ms
round 2 GET /account/keys n=260 p50=2.25ms p95=2.84ms mean=2.32ms
round 2 login/start n=30 p50=4.74ms p95=6.45ms mean=4.99ms
round 2 login/finish n=30 p50=6.50ms p95=11.78ms mean=7.73ms
exit 0
== ruvee-f19 run 3
round 0 GET /account/keys n=260 p50=1.44ms p95=1.76ms mean=1.47ms
round 0 login/start n=30 p50=2.26ms p95=2.92ms mean=2.32ms
round 0 login/finish n=30 p50=5.39ms p95=11.59ms mean=6.20ms
round 1 GET /account/keys n=260 p50=1.34ms p95=2.32ms mean=1.58ms
round 1 login/start n=30 p50=2.17ms p95=2.60ms mean=2.22ms
round 1 login/finish n=30 p50=5.40ms p95=7.07ms mean=5.53ms
round 2 GET /account/keys n=260 p50=1.25ms p95=1.73ms mean=1.38ms
round 2 login/start n=30 p50=2.36ms p95=3.12ms mean=2.37ms
round 2 login/finish n=30 p50=6.65ms p95=11.50ms mean=7.17ms
exit 0
== ruvee-limits run 3
round 0 GET /account/keys n=260 p50=2.68ms p95=6.18ms mean=3.14ms
round 0 login/start n=30 p50=5.48ms p95=12.70ms mean=6.41ms
round 0 login/finish n=30 p50=7.53ms p95=14.39ms mean=8.31ms
round 1 GET /account/keys n=260 p50=2.42ms p95=5.87ms mean=2.96ms
round 1 login/start n=30 p50=5.02ms p95=6.12ms mean=5.34ms
round 1 login/finish n=30 p50=6.65ms p95=11.74ms mean=7.85ms
round 2 GET /account/keys n=260 p50=2.34ms p95=4.16ms mean=2.58ms
round 2 login/start n=30 p50=5.05ms p95=7.85ms mean=5.63ms
round 2 login/finish n=30 p50=7.15ms p95=11.73ms mean=7.78ms
exit 0
```

## The spec (`measure-17-2.int-spec.ts`, SHA-256 `1d9640ac44df20e96ed2bf16d867891b8a8b8b281e44b0c86a4fb3770960a4ce`)

Run from `apps/api/test/review/` with `RUVEE_MEASURE_OUT=<file>`; not part of the test suite.

```ts
import { appendFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { loginStartResponseSchema } from '@ruvee/contracts';
import { ThrottleService } from '../../src/auth/throttle.service.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from '../support/api-harness.js';
import { signLogin } from '../support/device-proof.js';
import { finishLogin, startLogin, syntheticAccount } from '../support/synthetic-client.js';

/** Local latency sample (not a capacity claim): one process, supertest, task PostgreSQL. */
const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] ?? NaN;
};
const fmt = (xs: number[]) =>
  `n=${String(xs.length)} p50=${pct(xs, 50).toFixed(2)}ms p95=${pct(xs, 95).toFixed(2)}ms mean=${(xs.reduce((a, b) => a + b, 0) / xs.length).toFixed(2)}ms`;

describe('measure', () => {
  let h: Harness;
  let account: Awaited<ReturnType<typeof syntheticAccount>>;
  let cookie: string;
  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-measure');
    cookie = await registerAccount(h, account);
  }, 60_000);
  afterAll(async () => {
    await h.close();
  });

  it('authenticated GET and login', async () => {
    const out: string[] = [];
    for (let round = 0; round < 3; round++) {
      const gets: number[] = [];
      await h.app.get(ThrottleService).clearIpWindows();
      for (let i = 0; i < 280; i++) {
        const t = performance.now();
        const r = await h.get('/api/v1/account/keys', cookie);
        gets.push(performance.now() - t);
        if (r.status !== 200) throw new Error(`GET ${String(r.status)}`);
      }
      const starts: number[] = [];
      const finishes: number[] = [];
      for (let i = 0; i < 31; i++) {
        await h.app.get(ThrottleService).clearIpWindows();
        const client = startLogin();
        let t = performance.now();
        const res = await h.post('/api/v1/auth/login/start', {
          username: account.username,
          startLoginRequest: client.startLoginRequest,
          platform: 'web',
          deviceId: account.deviceId,
        });
        starts.push(performance.now() - t);
        const started = loginStartResponseSchema.parse(res.body);
        const finished = finishLogin(client.clientLoginState, started.loginResponse);
        if (!finished) throw new Error('opaque');
        const body = {
          loginId: started.loginId,
          finishLoginRequest: finished.finishLoginRequest,
          deviceProof: signLogin(account, started, finished.finishLoginRequest),
        };
        t = performance.now();
        const done = await h.post('/api/v1/auth/login/finish', body);
        finishes.push(performance.now() - t);
        if (done.status !== 200) throw new Error(`finish ${String(done.status)}`);
        cookie = sessionCookie(done);
      }
      out.push(`round ${String(round)} GET /account/keys ${fmt(gets.slice(20))}`);
      out.push(`round ${String(round)} login/start ${fmt(starts.slice(1))}`);
      out.push(`round ${String(round)} login/finish ${fmt(finishes.slice(1))}`);
    }
    appendFileSync(process.env.RUVEE_MEASURE_OUT ?? '/dev/null', `${out.join('\n')}\n`);
  }, 300_000);
});
```
