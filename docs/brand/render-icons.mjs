// Renders the PNG icons the platforms need from the mark's geometry (see ruvee-mark.svg).
// Uses the Playwright Chromium the web tests already install.
//
//   node docs/brand/render-icons.mjs
//     writes the web and extension icons inside this checkout only.
//   node docs/brand/render-icons.mjs --mobile-out <path to a mobile checkout>
//     also writes the iOS and Android icons under that path. Only with the flag: no other
//     checkout is ever written by default, and the path must already exist.
import { mkdir, stat, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';

const repo = resolve(import.meta.dirname, '../..');
const { values } = parseArgs({ options: { 'mobile-out': { type: 'string' } } });
const mobile = values['mobile-out'] === undefined ? undefined : resolve(values['mobile-out']);
if (mobile !== undefined && !(await stat(mobile).catch(() => undefined))?.isDirectory()) {
  console.error(`--mobile-out: ${mobile} is not an existing directory.`);
  process.exit(1);
}
const { chromium } = createRequire(resolve(repo, 'apps/web/package.json'))('@playwright/test');

const BRAND = '#6d4aff';

// shape: 'tile' (rounded square, transparent corners), 'square' (full bleed) or 'circle'.
// pad is transparent margin in 32-grid units. Below 48px the favicon's heavier stroke keeps the
// ring open.
function svg(size, shape, pad = 0) {
  const small = size < 48;
  const [cy, r, w, y1, y2] = small ? [13.2, 4.8, 3.2, 18.4, 24.8] : [13.5, 5, 2.6, 18.5, 24.5];
  const box = 32 + pad * 2;
  const bg =
    shape === 'circle'
      ? `<circle cx="16" cy="16" r="16" fill="${BRAND}"/>`
      : `<rect width="32" height="32" rx="${shape === 'tile' ? (small ? 8 : 9) : 0}" fill="${BRAND}"/>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="${-pad} ${-pad} ${box} ${box}">${bg}<circle cx="16" cy="${cy}" r="${r}" fill="none" stroke="#fff" stroke-width="${w}"/><path d="M16 ${y1}V${y2}" stroke="#fff" stroke-width="${w}" stroke-linecap="round"/></svg>`;
}

const android = (root, dir) => resolve(root, 'apps/mobile/app/android/app/src/main/res', dir);
const repoTargets = [
  // Web: Apple touch icon (iOS rounds it).
  [resolve(repo, 'apps/web/src/app/apple-icon.png'), 180, 'square'],
  // Extension: Chrome asks for 128px art with about 8px of transparent margin.
  ...[16, 32, 48].map((s) => [
    resolve(repo, `apps/extension/static/icons/icon-${s}.png`),
    s,
    'tile',
  ]),
  [resolve(repo, 'apps/extension/static/icons/icon-128.png'), 128, 'tile', 2],
];
const mobileTargets = (root) => [
  // iOS: one opaque 1024px icon; the system masks it.
  [
    resolve(
      root,
      'apps/mobile/app/ios/RuveeMobile/Images.xcassets/AppIcon.appiconset/AppIcon-1024.png',
    ),
    1024,
    'square',
  ],
  // Android before API 26 (API 26+ uses the adaptive vector in mipmap-anydpi-v26).
  ...[
    ['mdpi', 48],
    ['hdpi', 72],
    ['xhdpi', 96],
    ['xxhdpi', 144],
    ['xxxhdpi', 192],
  ].flatMap(([d, s]) => [
    [android(root, `mipmap-${d}/ic_launcher.png`), s, 'tile', 1],
    [android(root, `mipmap-${d}/ic_launcher_round.png`), s, 'circle', 1],
  ]),
];
const targets = [...repoTargets, ...(mobile === undefined ? [] : mobileTargets(mobile))];

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  for (const [file, size, shape, pad] of targets) {
    await page.setViewportSize({ width: size, height: size });
    await page.setContent(
      `<style>html,body{margin:0}svg{display:block}</style>${svg(size, shape, pad)}`,
    );
    const png = await page.locator('svg').screenshot({ omitBackground: shape !== 'square' });
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, png);
    console.log(`${size}px ${shape} -> ${file}`);
  }
} finally {
  await browser.close();
}
