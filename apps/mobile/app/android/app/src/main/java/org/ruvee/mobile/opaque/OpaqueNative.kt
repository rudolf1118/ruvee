package org.ruvee.mobile.opaque

/**
 * JNI declarations of the OPAQUE binding (native/opaque, libruvee_opaque.so): opaque-ke 4.0.1
 * with the D-02 configuration of @serenity-kit/opaque 1.1.0. Passwords are UTF-8 byte arrays;
 * the Rust side zeroes its copy. Every failure is an IllegalArgumentException with a fixed message.
 */
object OpaqueNative {
  init {
    System.loadLibrary("ruvee_opaque")
  }

  /** [state, registrationRequest] */
  external fun startRegistration(password: ByteArray): Array<String>

  /** registrationRecord */
  external fun finishRegistration(state: String, response: String, password: ByteArray): String

  /** [state, startLoginRequest] */
  external fun startLogin(password: ByteArray): Array<String>

  /** finishLoginRequest, or null when the client rejects the server's response. */
  external fun finishLogin(state: String, response: String, password: ByteArray): String?
}
