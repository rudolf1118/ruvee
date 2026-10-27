#!/usr/bin/env bash
# Runs the Stage 1 compatibility checks on a connected emulator or device and writes the summary
# JSON (ids, timings, error names; no key material) to the path given as $2.
#
#   RUVEE_WASM_PROBE=1 npx react-native start   # in another terminal (Metro, probe enabled)
#   scripts/compat-run.sh emulator-5584 /tmp/compat.json
set -euo pipefail
serial="${1:?serial}"
out="${2:?output path}"
here="$(cd "$(dirname "$0")" && pwd)"
adb="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"

"$adb" -s "$serial" reverse tcp:8081 tcp:8081 >/dev/null
"$adb" -s "$serial" shell am force-stop org.ruvee.mobile
"$adb" -s "$serial" logcat -c
"$adb" -s "$serial" shell am start -n org.ruvee.mobile/.MainActivity >/dev/null
node "$here/adb-ui.mjs" tap open-compat "$serial" >/dev/null
node "$here/adb-ui.mjs" tap compat-run "$serial" >/dev/null
for _ in $(seq 1 450); do
  if "$adb" -s "$serial" logcat -d -s ReactNativeJS:V | grep -q RUVEE_COMPAT_SUMMARY; then break; fi
  if "$adb" -s "$serial" logcat -d -s AndroidRuntime:E | grep -q "FATAL EXCEPTION"; then
    echo "app crashed" >&2
    exit 1
  fi
  sleep 2
done
"$adb" -s "$serial" logcat -d -s ReactNativeJS:V | grep RUVEE_COMPAT_SUMMARY | tail -1 | sed 's/.*RUVEE_COMPAT_SUMMARY //' > "$out"
node -e '
const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
for (const x of r.results)
  console.log(`${x.ok ? "PASS" : "FAIL"}  ${x.group} / ${x.id}  ${x.ms} ms  ${x.detail ?? ""}${x.error ?? ""}`);
console.log(`total ${r.total}, failed ${r.failed}`);
' "$out"
