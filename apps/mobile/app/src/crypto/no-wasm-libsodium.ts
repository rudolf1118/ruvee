/**
 * Stands in for `libsodium-wrappers-sumo` in the app bundle (metro.config.js). The app never calls
 * `initRuveeCrypto`, which loads the WebAssembly build; it builds the same operations over native
 * libsodium instead (./native-primitives.ts). Anything that still reaches for the WebAssembly build
 * fails here rather than running a second, unpinned crypto library.
 */
const unavailable = {
  get ready(): Promise<never> {
    return Promise.reject(new Error('libsodium.js is not bundled in the mobile app'));
  },
};

export default unavailable;
