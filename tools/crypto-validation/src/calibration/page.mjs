// Benchmark page: controller for one dedicated Web Worker at a time, plus a minimal UI for
// manual runs (Safari, phones). Synthetic inputs only.

import { CONFIGS, DEFAULT_ORDER, RUN_MODES, argon2Mapping, timerResolution } from './core.mjs';
import { INIT_SERIES, measureInit, runOne, testCancellation } from './controller.mjs';

const PARTIAL_KEY = 'ruvee-calibration-partial';
let active = null;
let userCancelled = false;

function createWorker() {
  const w = new Worker('/calibration/worker.js');
  let deliver = () => {};
  const handle = {
    post: (m) => w.postMessage(m),
    onMessage: (fn) => {
      deliver = fn;
      w.onmessage = (e) => fn(e.data);
      w.onerror = (e) => {
        e.preventDefault?.();
        fn({
          type: 'error',
          error: `worker error: ${e.message || 'unknown (possibly out of memory)'}`,
        });
      };
    },
    terminate: () => {
      w.terminate();
      if (active === handle) active = null;
    },
    abort: () => {
      w.terminate();
      deliver({ type: 'error', error: 'cancelled by the user' });
    },
  };
  active = handle;
  return handle;
}

export function cancelRun() {
  userCancelled = true;
  active?.abort();
}

async function environment() {
  const n = globalThis.navigator;
  let uaData = null;
  if (n.userAgentData?.getHighEntropyValues) {
    try {
      uaData = await n.userAgentData.getHighEntropyValues([
        'architecture',
        'model',
        'platformVersion',
        'fullVersionList',
      ]);
    } catch {
      uaData = null;
    }
  }
  return {
    runtime: 'browser',
    scope: 'dedicated Web Worker, a fresh worker per configuration',
    userAgent: n.userAgent,
    userAgentData: uaData,
    hardwareConcurrency: n.hardwareConcurrency ?? null,
    deviceMemoryGiB: n.deviceMemory ?? null,
    crossOriginIsolated: globalThis.crossOriginIsolated === true,
    secureContext: globalThis.isSecureContext === true,
    mainThreadTimerResolutionMs: timerResolution(() => performance.now()),
    packages: __PACKAGES__,
  };
}

const store = (report) => {
  try {
    localStorage.setItem(PARTIAL_KEY, JSON.stringify(report));
  } catch {
    // storage may be unavailable (private mode); results are still returned
  }
};

export async function runCalibration({
  mode = 'standard',
  configIds = DEFAULT_ORDER,
  cancellation = true,
  deviceLabel = '',
  onEvent = () => {},
} = {}) {
  userCancelled = false;
  const report = {
    kind: 'argon2id-calibration',
    deviceLabel: String(deviceLabel).slice(0, 200),
    environment: await environment(),
    startedAt: new Date().toISOString(),
    mode: { name: mode, ...RUN_MODES[mode] },
    order: configIds,
    configurations: CONFIGS.map((c) => ({ ...c, mapping: argon2Mapping(c) })),
    results: [],
    complete: false,
  };
  onEvent({ step: 'init', text: `Worker initialisation (${INIT_SERIES} workers)` });
  report.init = await measureInit(createWorker);
  store(report);
  for (const id of configIds) {
    if (userCancelled) break;
    onEvent({ step: 'config', id, text: `Measuring ${id}` });
    const r = await runOne(createWorker, id, mode, (p) => onEvent({ step: 'progress', ...p }));
    report.results.push(r);
    store(report);
    onEvent({ step: 'config-done', id, result: r });
  }
  if (cancellation && !userCancelled) {
    onEvent({ step: 'cancellation', text: 'Cancellation and cleanup test' });
    try {
      report.cancellation = await testCancellation(createWorker);
    } catch (e) {
      report.cancellation = { passed: false, error: String(e?.message ?? e) };
    }
  }
  report.userCancelled = userCancelled;
  report.complete = !userCancelled;
  report.finishedAt = new Date().toISOString();
  store(report);
  return report;
}

globalThis.runCalibration = runCalibration;

// ---- Manual UI -------------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);
const el = (tag, text) => {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = String(text);
  return e;
};

function renderResults(report) {
  const body = $('results-body');
  body.replaceChildren();
  for (const r of report.results) {
    const tr = el('tr');
    const s = r.stats ?? {};
    for (const v of [
      r.configId,
      r.status,
      s.median ?? '',
      s.p95 ?? '',
      s.min ?? '',
      s.max ?? '',
      s.n ?? 0,
      r.failures?.length ? r.failures.map((f) => f.error).join('; ') : '',
    ])
      tr.append(el('td', v));
    body.append(tr);
  }
  $('json').value = JSON.stringify(report, null, 2);
}

async function sendToComputer(report) {
  const res = await fetch('/results', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(report),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()).saved;
}

function setupUi() {
  if (!$('start')) return;
  const list = $('configs');
  for (const c of CONFIGS) {
    const label = el('label');
    const box = el('input');
    box.type = 'checkbox';
    box.value = c.id;
    box.checked = true;
    label.append(box, ` ${c.id} (${c.memlimit / 1048576} MiB, t = ${c.opslimit}, ${c.role})`);
    list.append(label);
  }
  try {
    const partial = JSON.parse(localStorage.getItem(PARTIAL_KEY) ?? 'null');
    if (partial && !partial.complete) {
      $('status').textContent =
        'A previous run did not finish. Its partial results are shown below.';
      renderResults(partial);
    }
  } catch {
    // ignore unreadable partial results
  }
  $('cancel').addEventListener('click', () => cancelRun());
  $('start').addEventListener('click', async () => {
    $('start').disabled = true;
    $('cancel').disabled = false;
    const chosen = new Set([...list.querySelectorAll('input:checked')].map((b) => b.value));
    const configIds = DEFAULT_ORDER.filter((id) => chosen.has(id));
    const report = await runCalibration({
      mode: $('mode').value,
      configIds,
      cancellation: $('with-cancellation').checked,
      deviceLabel: $('device').value,
      onEvent: (e) => {
        if (e.text) $('status').textContent = e.text;
        if (e.step === 'progress')
          $('status').textContent =
            `${e.configId}: ${e.kind} ${e.index + 1} took ${Math.round(e.ms)} ms`;
      },
    });
    renderResults(report);
    $('status').textContent = report.complete ? 'Finished.' : 'Stopped.';
    try {
      $('status').textContent += ` Saved on the computer as ${await sendToComputer(report)}.`;
    } catch (e) {
      $('status').textContent +=
        ` Could not send to the computer (${e.message}); copy the JSON below.`;
    }
    $('start').disabled = false;
    $('cancel').disabled = true;
  });
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setupUi);
  else setupUi();
}
