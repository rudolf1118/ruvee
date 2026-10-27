package org.ruvee.mobile.opaque

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap

/**
 * `NativeModules.RuveeOpaque`: the OPAQUE client the vault engine calls (`OpaqueClient` in
 * packages/vault). Synchronous, like @serenity-kit/opaque on the web, so the engine is unchanged;
 * a call blocks the JavaScript thread for one Argon2id (the "memory-constrained" preset) at most.
 *
 * The password arrives as a JavaScript string and is encoded to UTF-8 here, the bytes
 * @serenity-kit/opaque hashes for the same well-formed string (the engine refuses lone
 * surrogates first). The byte copy is zeroed after the call; the strings cannot be.
 */
class OpaqueModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context) {
  override fun getName() = "RuveeOpaque"

  private inline fun <T> withPassword(password: String, run: (ByteArray) -> T): T {
    val bytes = password.toByteArray(Charsets.UTF_8)
    try {
      return run(bytes)
    } finally {
      bytes.fill(0)
    }
  }

  private fun started(pair: Array<String>): WritableMap =
    Arguments.createMap().apply {
      putString("state", pair[0])
      putString("request", pair[1])
    }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun startRegistration(password: String): WritableMap =
    started(withPassword(password) { OpaqueNative.startRegistration(it) })

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun finishRegistration(state: String, response: String, password: String): String =
    withPassword(password) { OpaqueNative.finishRegistration(state, response, it) }

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun startLogin(password: String): WritableMap =
    started(withPassword(password) { OpaqueNative.startLogin(it) })

  @ReactMethod(isBlockingSynchronousMethod = true)
  fun finishLogin(state: String, response: String, password: String): String? =
    withPassword(password) { OpaqueNative.finishLogin(state, response, it) }
}
