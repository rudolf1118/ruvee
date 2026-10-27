# Running the mobile app and its tests

Android only. iOS needs Xcode, which the development machine does not have. Synthetic data only.
All commands run from the repository root unless a `cd` says otherwise.

## 1. One-time toolchain (task-owned, nothing global)

The Android build needs NDK 27.1.12297006 and CMake 3.22.1, and the OPAQUE binding needs Rust. On
the development machine they live in `.mobile-toolchain/` at the worktree root (gitignored by its
own `.gitignore`), next to symlinks to the platforms and build tools of the existing Android SDK:

```bash
T=.mobile-toolchain; mkdir -p $T/downloads $T/sdk/ndk $T/sdk/cmake $T/sdk/build-tools $T/sdk/platforms && printf '*\n' > $T/.gitignore
```

```bash
cd .mobile-toolchain/downloads && curl -sSO https://dl.google.com/android/repository/android-ndk-r27b-darwin.zip && echo "c70c9791b0d258858678f6df31c4319140e2926e  android-ndk-r27b-darwin.zip" | shasum -a 1 -c - && curl -sSO https://dl.google.com/android/repository/cmake-3.22.1-darwin.zip && echo "8604eeef9adadb626dbb70a7ff58a87e6a7b967a  cmake-3.22.1-darwin.zip" | shasum -a 1 -c -
```

Unzip the NDK to `sdk/ndk/27.1.12297006` and CMake to `sdk/cmake/3.22.1`; symlink
`platforms/android-37.0`, `build-tools/36.1.0` and `platform-tools` from `~/Library/Android/sdk`;
copy `licenses`. Rust: download `rustup-init` for `aarch64-apple-darwin`, check its `.sha256`, and
run it with `RUSTUP_HOME=$T/rust/rustup CARGO_HOME=$T/rust/cargo ... -y --no-modify-path --profile
minimal`, then `rustup target add aarch64-linux-android`.

`apps/mobile/app/scripts/android-env.sh` points Gradle at that SDK and at Android Studio's bundled
Java; `scripts/build-opaque-android.sh` uses the Rust toolchain and NDK from the same folder.

## 2. Build and launch the app

```bash
cd apps/mobile/app && npm ci && node scripts/embed-compat-vectors.mjs && scripts/build-opaque-android.sh
```

```bash
cd apps/mobile/app && . scripts/android-env.sh && (cd android && ./gradlew :app:assembleDebug)
```

A task-owned emulator (`.mobile-toolchain/avd/ruvee-task-mobile`, from the installed
`android-36.1` arm64 system image; it never touches the AVDs in `~/.android`):

```bash
ANDROID_AVD_HOME=$PWD/.mobile-toolchain/avd ANDROID_SDK_ROOT=$HOME/Library/Android/sdk ~/Library/Android/sdk/emulator/emulator -avd ruvee-task-mobile -port 5584 -no-snapshot -no-window -no-audio -gpu swiftshader_indirect
```

```bash
cd apps/mobile/app && adb -s emulator-5584 install -r android/app/build/outputs/apk/debug/app-debug.apk && adb -s emulator-5584 reverse tcp:8081 tcp:8081
```

```bash
cd apps/mobile/app && RUVEE_WASM_PROBE=1 npx react-native start --port 8081
```

`RUVEE_WASM_PROBE=1` bundles libsodium.js for the compatibility runner's comparisons; without it the
app bundle replaces libsodium.js with a module that throws. Start the app from the launcher or with
`adb shell am start -n org.ruvee.mobile/.MainActivity`.

To use the app by hand against a local server, serve the web export with its `/api` proxy on a
loopback port, `adb reverse` that port, and enter `http://127.0.0.1:<port>` as the server address
(development builds only).

## 3. Checks

| What                                                   | Command                                                                                                                      | Needs                               |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Type-check the app (and the shared sources it bundles) | `cd apps/mobile/app && npx tsc --noEmit`                                                                                     | `npm ci`                            |
| OPAQUE binding unit test                               | `cd apps/mobile/app/native/opaque && RUSTUP_HOME=… CARGO_HOME=… cargo test --release`                                        | Rust                                |
| OPAQUE interop with @serenity-kit/opaque               | `cd apps/mobile/app/native/opaque && cargo build --release --example interop && cd ../.. && node scripts/opaque-interop.mjs` | Rust, `npm ci`                      |
| Stage 1 compatibility runner, on device                | `cd apps/mobile/app && scripts/compat-run.sh emulator-5584 /tmp/compat.json`                                                 | Emulator, app, Metro with the probe |
| End-to-end suite                                       | see §4                                                                                                                       | Everything above, Docker            |
| Type-check the E2E harness                             | `cd apps/mobile/e2e && npx tsc -p tsconfig.json`                                                                             | `npm ci`                            |

### Stage 1 compatibility runner

`scripts/compat-run.sh` force-stops the app, opens the development-only "Native compatibility
checks" screen, runs it, and prints one line per check; the summary JSON goes to the given file.
It takes about 1.5 minutes plus 50 seconds for the deliberately slow pure-JS Argon2id comparison.

## 4. End-to-end suite

Framework: **Appium 3.8.0** with the **UiAutomator2 driver 8.7.0** (driving the installed app,
black-box, with real process termination and backgrounding) through **WebdriverIO 10.0.2**, and
**Playwright 1.64.1** driving the real web app in Chromium as the other device; Node's built-in test
runner. All pinned in `apps/mobile/e2e/package-lock.json`. Appium's driver home is
`.mobile-toolchain/appium`.

Backend: the repository's own `apps/api/scripts/e2e-stack.mjs` (unchanged) creates a throwaway
`ruvee_e2e_*` database on the PostgreSQL server you give it, migrates it, writes an OPAQUE setup
and a bootstrap token, runs the built API, and drops it all on exit. Use a task-owned container:

```bash
docker run -d --name ruvee-task-mobile-pg --label ruvee.task=mobile-vault -e POSTGRES_USER=ruvee_task -e POSTGRES_PASSWORD=<synthetic> -e POSTGRES_DB=ruvee_task -p 127.0.0.1:56110:5432 postgres:18-alpine
```

```bash
pnpm install --frozen-lockfile && pnpm turbo run build --filter=@ruvee/api --filter=@ruvee/web
```

```bash
cd apps/mobile/e2e && npm ci && APPIUM_HOME=$PWD/../../../.mobile-toolchain/appium npx appium driver install uiautomator2@8.7.0
```

With the emulator booted, the debug app installed and Metro running:

```bash
cd apps/mobile/e2e && RUVEE_E2E_ADMIN_DATABASE_URL=postgresql://ruvee_task:<synthetic>@127.0.0.1:56110/ruvee_task npm test
```

Variables: `RUVEE_E2E_SERIAL` (default `emulator-5584`), `RUVEE_E2E_WEB_PORT` (3171),
`RUVEE_E2E_API_PORT` (4171), `RUVEE_E2E_APPIUM_PORT` (4723), `RUVEE_E2E_ARTIFACTS` (screenshots
of a failed step). The suite clears the app's data first (`pm clear`), starts and stops its own
Appium server and backend, and leaves no database behind.

"Offline" is simulated by removing the `adb reverse` rule for the server port: the app's
connections to `127.0.0.1:<port>` are then refused, exactly as with no route to the server.

## 5. Cleanup of task-owned resources

```bash
docker rm -f -v ruvee-task-mobile-pg
```

```bash
adb -s emulator-5584 emu kill
```

Then delete `.mobile-toolchain/` (NDK, CMake, Rust, Appium driver, the AVD and its data disk: about 6 GB). The developer's
Android SDK, AVDs and `~/.gradle` cache are not modified, except that Gradle downloaded the
dependencies of this build (React Native's Maven artifacts, Gradle 9.4.1) into the shared cache, as
any Android build does.
