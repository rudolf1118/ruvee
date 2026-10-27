// The phone, driven through Appium's UiAutomator2 driver: black-box, against the installed app,
// with real process termination and backgrounding. Elements are found by React Native testID,
// which Android exposes as the view's resource-id.

import { spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { remote } from 'webdriverio';
import { APP_ID } from './adb.ts';

type Driver = Awaited<ReturnType<typeof remote>>;

const e2eRoot = fileURLToPath(new URL('../', import.meta.url));
const appiumHome = fileURLToPath(new URL('../../../../.mobile-toolchain/appium', import.meta.url));

export async function startAppium(port: number): Promise<{ stop: () => Promise<void> }> {
  const child: ChildProcess = spawn(
    join(e2eRoot, 'node_modules/.bin/appium'),
    [
      '--address',
      '127.0.0.1',
      '--port',
      String(port),
      '--log-level',
      'error',
      '--relaxed-security',
    ],
    {
      env: { ...process.env, APPIUM_HOME: process.env.APPIUM_HOME ?? appiumHome },
      stdio: 'ignore',
    },
  );
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      const res = await fetch(`http://127.0.0.1:${String(port)}/status`);
      if (res.ok) break;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error('Appium did not start');
    await new Promise((r) => setTimeout(r, 500));
  }
  return {
    stop: () =>
      new Promise<void>((resolve) => {
        child.once('exit', () => resolve());
        child.kill('SIGTERM');
      }),
  };
}

export class Phone {
  readonly driver: Driver;
  private readonly artifacts: string;

  private constructor(driver: Driver, artifacts: string) {
    this.driver = driver;
    this.artifacts = artifacts;
  }

  static async connect(params: {
    appiumPort: number;
    serial: string;
    artifacts: string;
  }): Promise<Phone> {
    const driver = await remote({
      hostname: '127.0.0.1',
      port: params.appiumPort,
      logLevel: 'error',
      connectionRetryTimeout: 240_000,
      capabilities: {
        platformName: 'Android',
        'appium:automationName': 'UiAutomator2',
        'appium:udid': params.serial,
        'appium:appPackage': APP_ID,
        'appium:appActivity': '.MainActivity',
        'appium:noReset': true,
        'appium:newCommandTimeout': 900,
        'appium:disableWindowAnimation': true,
        'appium:uiautomator2ServerLaunchTimeout': 120_000,
      },
    });
    mkdirSync(params.artifacts, { recursive: true });
    return new Phone(driver, params.artifacts);
  }

  private el(testID: string) {
    return this.driver.$(`android=new UiSelector().resourceId("${testID}")`);
  }

  async waitFor(testID: string, timeout = 30_000): Promise<void> {
    await this.el(testID).waitForDisplayed({ timeout });
  }

  async tap(testID: string, timeout = 30_000): Promise<void> {
    const el = this.el(testID);
    await el.waitForDisplayed({ timeout });
    await el.click();
  }

  /** Replaces the field's text (secure fields included: appending to them is unreliable). */
  async type(testID: string, text: string): Promise<void> {
    const el = this.el(testID);
    await el.waitForDisplayed({ timeout: 30_000 });
    await this.driver.execute('mobile: replaceElementValue', {
      elementId: await el.elementId,
      text,
    });
    await this.driver.hideKeyboard().catch(() => undefined);
  }

  async text(testID: string, timeout = 30_000): Promise<string> {
    const el = this.el(testID);
    await el.waitForDisplayed({ timeout });
    return el.getText();
  }

  async isShown(testID: string): Promise<boolean> {
    return this.el(testID)
      .isDisplayed()
      .catch(() => false);
  }

  /** Waits until some visible text contains `fragment`. */
  async waitForText(fragment: string, timeout = 30_000): Promise<void> {
    await this.driver
      .$(`android=new UiSelector().textContains(${JSON.stringify(fragment)})`)
      .waitForDisplayed({ timeout, timeoutMsg: `text not shown: ${fragment}` });
  }

  async waitUntilText(
    testID: string,
    predicate: (text: string) => boolean,
    timeout = 30_000,
  ): Promise<string> {
    let last = '';
    await this.driver.waitUntil(
      async () => {
        last = await this.el(testID)
          .getText()
          .catch(() => '');
        return predicate(last);
      },
      { timeout, interval: 700, timeoutMsg: `${testID} never matched; last: ${last}` },
    );
    return last;
  }

  /** Home button, then back to the app, as a user switching apps would. */
  async background(seconds: number): Promise<void> {
    await this.driver.execute('mobile: pressKey', { keycode: 3 });
    await new Promise((r) => setTimeout(r, seconds * 1000));
    await this.driver.activateApp(APP_ID);
  }

  /** Kills the process (as the OS does under memory pressure) and starts it again. */
  async restart(): Promise<void> {
    await this.driver.terminateApp(APP_ID);
    await this.driver.activateApp(APP_ID);
  }

  async screenshot(name: string): Promise<void> {
    const png = await this.driver.takeScreenshot();
    writeFileSync(join(this.artifacts, `${name}.png`), png, 'base64');
  }

  async close(): Promise<void> {
    await this.driver.deleteSession().catch(() => undefined);
  }
}
