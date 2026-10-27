#!/usr/bin/env bash
# Builds the OPAQUE binding (native/opaque) for Android and puts the library where Gradle packages
# it. Uses the Rust toolchain and NDK from <worktree>/.mobile-toolchain unless RUSTUP_HOME,
# CARGO_HOME or ANDROID_NDK_HOME are set. arm64-v8a only (the emulator and current phones);
# add targets to TARGETS for others.
set -euo pipefail
app="$(cd "$(dirname "$0")/.." && pwd)"
toolchain="$(cd "$app/../../.." && pwd)/.mobile-toolchain"
export RUSTUP_HOME="${RUSTUP_HOME:-$toolchain/rust/rustup}"
export CARGO_HOME="${CARGO_HOME:-$toolchain/rust/cargo}"
export PATH="$CARGO_HOME/bin:$PATH"
ndk="${ANDROID_NDK_HOME:-$toolchain/sdk/ndk/27.1.12297006}"
llvm="$ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin"
min_api=24

abi_of() {
  case "$1" in
    aarch64-linux-android) echo arm64-v8a ;;
    x86_64-linux-android) echo x86_64 ;;
    *) echo "unknown target $1" >&2; exit 1 ;;
  esac
}
TARGETS=(aarch64-linux-android)

for target in "${TARGETS[@]}"; do
  upper="$(echo "$target" | tr 'a-z-' 'A-Z_')"
  export "CARGO_TARGET_${upper}_LINKER=$llvm/${target}${min_api}-clang"
  export "CC_${target//-/_}=$llvm/${target}${min_api}-clang"
  export "AR_${target//-/_}=$llvm/llvm-ar"
  (cd "$app/native/opaque" && cargo build --release --locked --target "$target" --lib)
  out="$app/android/app/src/main/jniLibs/$(abi_of "$target")"
  mkdir -p "$out"
  cp "$app/native/opaque/target/$target/release/libruvee_opaque.so" "$out/"
  echo "built $out/libruvee_opaque.so"
done
