import * as Keychain from 'react-native-keychain';

/**
 * OS-protected storage for the two device secrets that must survive a restart
 * (docs/mobile/storage-policy.md):
 *
 * - `SK`, the Secret Key (device-enrollment.md §5);
 * - the refresh token (authentication.md §5).
 *
 * Android: react-native-keychain 10.0.0 with `AES_GCM_NO_AUTH`: an AES-256-GCM key generated in
 * AndroidKeyStore (StrongBox first, then the TEE or software Keystore), never exportable; only
 * the ciphertext is written, to the app's private DataStore file, which is excluded from backup
 * and device transfer. Whether the key is inside secure hardware is reported by
 * `securityLevel()`, never assumed. iOS (not built or run here): a Keychain item with
 * `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
 *
 * The library's API carries values as strings, so a secret crosses the JS heap as base64 and that
 * string cannot be zeroed; the bytes returned are the caller's to wipe.
 */
const SERVICE_PREFIX = 'org.ruvee.mobile.';
const ACCOUNT = 'ruvee';

const setOptions = (name: string): Keychain.SetOptions => ({
  service: SERVICE_PREFIX + name,
  accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  storage: Keychain.STORAGE_TYPE.AES_GCM_NO_AUTH,
  securityLevel: Keychain.SECURITY_LEVEL.SECURE_SOFTWARE,
  cloudSync: false,
});

function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromB64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

export class SecureStoreError extends Error {
  constructor(readonly operation: 'read' | 'write' | 'remove') {
    // Never the library's message: it can name the service or describe the stored value.
    super(`secure storage ${operation} failed`);
    this.name = 'SecureStoreError';
  }
}

export const secureStore = {
  async getBytes(name: string): Promise<Uint8Array | undefined> {
    const text = await this.getText(name);
    return text === undefined ? undefined : fromB64(text);
  },

  async setBytes(name: string, value: Uint8Array): Promise<void> {
    await this.setText(name, toB64(value));
  },

  async getText(name: string): Promise<string | undefined> {
    let result: false | Keychain.UserCredentials;
    try {
      result = await Keychain.getGenericPassword({ service: SERVICE_PREFIX + name });
    } catch {
      throw new SecureStoreError('read');
    }
    return result === false ? undefined : result.password;
  },

  async setText(name: string, value: string): Promise<void> {
    try {
      const ok = await Keychain.setGenericPassword(ACCOUNT, value, setOptions(name));
      if (ok === false) throw new Error();
    } catch {
      throw new SecureStoreError('write');
    }
  },

  async remove(name: string): Promise<void> {
    try {
      await Keychain.resetGenericPassword({ service: SERVICE_PREFIX + name });
    } catch {
      throw new SecureStoreError('remove');
    }
  },

  /** Names (without the prefix) of every item this app holds. */
  async names(): Promise<string[]> {
    try {
      const services = await Keychain.getAllGenericPasswordServices();
      return services
        .filter((s) => s.startsWith(SERVICE_PREFIX))
        .map((s) => s.slice(SERVICE_PREFIX.length));
    } catch {
      throw new SecureStoreError('read');
    }
  },

  /** What the platform reports for a key generated with these options; reported, not assumed. */
  async securityLevel(): Promise<'secure_hardware' | 'secure_software' | 'any' | 'unknown'> {
    try {
      const level = await Keychain.getSecurityLevel({
        storage: Keychain.STORAGE_TYPE.AES_GCM_NO_AUTH,
      } as never);
      if (level === Keychain.SECURITY_LEVEL.SECURE_HARDWARE) return 'secure_hardware';
      if (level === Keychain.SECURITY_LEVEL.SECURE_SOFTWARE) return 'secure_software';
      if (level === Keychain.SECURITY_LEVEL.ANY) return 'any';
      return 'unknown';
    } catch {
      return 'unknown';
    }
  },
};
