// Minimal adb UI driver for development checks: taps an element by its React Native testID
// (exposed as the Android resource-id) or waits for text. Usage:
//   node scripts/adb-ui.mjs tap <testID> [serial]
//   node scripts/adb-ui.mjs wait-text <substring> <timeoutSeconds> [serial]
//   node scripts/adb-ui.mjs dump [serial]
// It reads the view hierarchy with `uiautomator dump`; it never reads app storage.

import { execFileSync } from 'node:child_process';

const [command, arg, third, fourth] = process.argv.slice(2);
const adb = `${process.env.ANDROID_HOME ?? `${process.env.HOME}/Library/Android/sdk`}/platform-tools/adb`;

function serialArg(serial) {
  return serial ? ['-s', serial] : [];
}

function dump(serial) {
  execFileSync(
    adb,
    [...serialArg(serial), 'shell', 'uiautomator', 'dump', '/sdcard/ruvee-ui.xml'],
    {
      stdio: 'ignore',
    },
  );
  return execFileSync(adb, [
    ...serialArg(serial),
    'exec-out',
    'cat',
    '/sdcard/ruvee-ui.xml',
  ]).toString('utf8');
}

function nodes(xml) {
  return [...xml.matchAll(/<node [^>]*>/g)].map((m) => {
    const attrs = {};
    for (const a of m[0].matchAll(/([\w-]+)="([^"]*)"/g)) attrs[a[1]] = a[2];
    return attrs;
  });
}

function center(bounds) {
  const [x1, y1, x2, y2] = bounds.match(/\d+/g).map(Number);
  return [Math.round((x1 + x2) / 2), Math.round((y1 + y2) / 2)];
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (command === 'tap') {
  const serial = third;
  for (let i = 0; i < 20; i++) {
    const node = nodes(dump(serial)).find(
      (n) => n['resource-id'] === arg || n['resource-id']?.endsWith(`:id/${arg}`),
    );
    if (node) {
      const [x, y] = center(node.bounds);
      execFileSync(adb, [...serialArg(serial), 'shell', 'input', 'tap', String(x), String(y)]);
      console.log(`tapped ${arg} at ${x},${y}`);
      process.exit(0);
    }
    await sleep(1000);
  }
  console.error(`no element with testID ${arg}`);
  process.exit(1);
} else if (command === 'wait-text') {
  const serial = fourth;
  const deadline = Date.now() + Number(third) * 1000;
  while (Date.now() < deadline) {
    const hit = nodes(dump(serial)).find((n) => n.text?.includes(arg));
    if (hit) {
      console.log(hit.text);
      process.exit(0);
    }
    await sleep(2000);
  }
  console.error(`text not found: ${arg}`);
  process.exit(1);
} else if (command === 'dump') {
  for (const n of nodes(dump(arg)))
    if (n.text || n['resource-id'])
      console.log(`${n['resource-id'] ?? ''} | ${n.text ?? ''} | ${n.bounds}`);
} else {
  console.error('usage: adb-ui.mjs tap <testID> | wait-text <text> <seconds> | dump');
  process.exit(2);
}
