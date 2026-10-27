# Source this file (`. scripts/android-env.sh`) before Gradle or the React Native CLI.
#
# It points the build at a task-owned Android SDK overlay in <worktree>/.mobile-toolchain/sdk:
# NDK 27.1.12297006 and CMake 3.22.1 downloaded there (SHA-1 checked against Google's repository
# manifest), plus symlinks to the platforms, build tools and platform-tools already installed in
# the developer's SDK. Nothing is written to the developer's own SDK. Without the overlay it falls
# back to ANDROID_HOME. Java comes from Android Studio's bundled runtime unless JAVA_HOME is set.

_ruvee_app="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
_ruvee_overlay="$(cd "$_ruvee_app/../../.." && pwd)/.mobile-toolchain/sdk"
if [ -d "$_ruvee_overlay/ndk" ]; then
  export ANDROID_HOME="$_ruvee_overlay"
  export ANDROID_SDK_ROOT="$_ruvee_overlay"
fi
if [ -z "${JAVA_HOME:-}" ] && [ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$_ruvee_app/android/local.properties"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
unset _ruvee_app _ruvee_overlay
