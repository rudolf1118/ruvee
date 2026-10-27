// adb operations the tests need that a UI driver does not offer: the loopback tunnel that stands
// for the network, the device log, and read access to the debug app's own files (`run-as`, debug
// builds only) for the storage scan.

import { execFileSync } from 'node:child_process';

export const APP_ID = 'org.ruvee.mobile';
const adbPath = `${process.env.ANDROID_HOME ?? `${process.env.HOME ?? ''}/Library/Android/sdk`}/platform-tools/adb`;

export function adb(serial: string, args: readonly string[], input?: Buffer): Buffer {
  return execFileSync(adbPath, ['-s', serial, ...args], {
    maxBuffer: 256 * 1024 * 1024,
    ...(input ? { input } : {}),
  });
}

/** The phone's `127.0.0.1:devicePort` reaches `127.0.0.1:hostPort` on this machine. */
export function reverse(serial: string, devicePort: number, hostPort: number): void {
  adb(serial, ['reverse', `tcp:${String(devicePort)}`, `tcp:${String(hostPort)}`]);
}

export function unreverse(serial: string, devicePort: number): void {
  try {
    adb(serial, ['reverse', '--remove', `tcp:${String(devicePort)}`]);
  } catch {
    // already removed
  }
}

export function clearLog(serial: string): void {
  adb(serial, ['logcat', '-b', 'all', '-c']);
}

/**
 * Every log buffer, every priority, except the lines written by the test instrumentation itself
 * (Appium's UiAutomator2 server and its helper app), which log the screen text they read back,
 * revealed passwords included. Lines are filtered by Android UID, so the app's lines and every
 * system process's lines are always kept.
 */
export function deviceLog(serial: string): { text: string; excludedLines: number } {
  const testUids = new Set(
    adb(serial, ['shell', 'pm', 'list', 'packages', '-U'])
      .toString('utf8')
      .split('\n')
      .filter((l) => /package:io\.appium\./.test(l))
      .map((l) => /uid:(\d+)/.exec(l)?.[1])
      .filter((u): u is string => u !== undefined),
  );
  const lines = adb(serial, ['logcat', '-b', 'all', '-d', '-v', 'brief', '-v', 'uid'])
    .toString('utf8')
    .split('\n');
  const kept = lines.filter((line) => {
    const uid = /^[VDIWEFA]\/[^(]*\(\s*([^:\s]+):/.exec(line)?.[1];
    return uid === undefined || !testUids.has(uid);
  });
  return { text: kept.join('\n'), excludedLines: lines.length - kept.length };
}

export function clearAppData(serial: string): void {
  adb(serial, ['shell', 'pm', 'clear', APP_ID]);
}

/** Every file in the app's private data directory, with its bytes. Debug builds only. */
export function appFiles(serial: string): Map<string, Buffer> {
  const list = adb(serial, ['shell', 'run-as', APP_ID, 'find', '.', '-type', 'f'])
    .toString('utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  const files = new Map<string, Buffer>();
  for (const path of list)
    files.set(path, adb(serial, ['exec-out', 'run-as', APP_ID, 'cat', path]));
  return files;
}

/** Whether `needle` occurs in `haystack` as UTF-8 or as UTF-16LE. */
export function contains(haystack: Buffer, needle: string): boolean {
  return (
    haystack.includes(Buffer.from(needle, 'utf8')) ||
    haystack.includes(Buffer.from(needle, 'utf16le'))
  );
}
