//! JNI entry points for `org.ruvee.mobile.opaque.OpaqueNative` (android/app/src/main/java).
//!
//! Passwords cross JNI as UTF-8 byte arrays (Kotlin encodes the JavaScript string), never as JNI
//! strings, whose "modified UTF-8" would encode characters outside the BMP differently from the
//! UTF-8 the web client hashes. The password copy made here is zeroed before returning.
//! Errors become one `IllegalArgumentException` with a fixed message: nothing about the input is
//! reported.

pub mod core;

use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::sys::{jobjectArray, jstring};
use jni::JNIEnv;
use zeroize::Zeroize;

const FAILED: &str = "opaque operation failed";

fn throw(env: &mut JNIEnv) {
    let _ = env.throw_new("java/lang/IllegalArgumentException", FAILED);
}

fn bytes(env: &mut JNIEnv, array: &JByteArray) -> Option<Vec<u8>> {
    env.convert_byte_array(array).ok()
}

fn text(env: &mut JNIEnv, value: &JString) -> Option<String> {
    env.get_string(value).ok().map(Into::into)
}

fn pair(env: &mut JNIEnv, started: core::Started) -> Option<jobjectArray> {
    let class = env.find_class("java/lang/String").ok()?;
    let array: JObjectArray = env.new_object_array(2, class, jni::objects::JObject::null()).ok()?;
    let state = env.new_string(started.state).ok()?;
    let request = env.new_string(started.request).ok()?;
    env.set_object_array_element(&array, 0, state).ok()?;
    env.set_object_array_element(&array, 1, request).ok()?;
    Some(array.into_raw())
}

fn start(
    env: &mut JNIEnv,
    password: JByteArray,
    run: fn(&[u8]) -> Result<core::Started, core::OpaqueError>,
) -> jobjectArray {
    let Some(mut pw) = bytes(env, &password) else {
        throw(env);
        return std::ptr::null_mut();
    };
    let result = run(&pw);
    pw.zeroize();
    match result.ok().and_then(|started| pair(env, started)) {
        Some(array) => array,
        None => {
            throw(env);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_ruvee_mobile_opaque_OpaqueNative_startRegistration(
    mut env: JNIEnv,
    _class: JClass,
    password: JByteArray,
) -> jobjectArray {
    start(&mut env, password, core::start_registration)
}

#[no_mangle]
pub extern "system" fn Java_org_ruvee_mobile_opaque_OpaqueNative_startLogin(
    mut env: JNIEnv,
    _class: JClass,
    password: JByteArray,
) -> jobjectArray {
    start(&mut env, password, core::start_login)
}

#[no_mangle]
pub extern "system" fn Java_org_ruvee_mobile_opaque_OpaqueNative_finishRegistration(
    mut env: JNIEnv,
    _class: JClass,
    state: JString,
    response: JString,
    password: JByteArray,
) -> jstring {
    let (Some(state), Some(response), Some(mut pw)) = (
        text(&mut env, &state),
        text(&mut env, &response),
        bytes(&mut env, &password),
    ) else {
        throw(&mut env);
        return std::ptr::null_mut();
    };
    let result = core::finish_registration(&state, &response, &pw);
    pw.zeroize();
    match result.ok().and_then(|record| env.new_string(record).ok()) {
        Some(record) => record.into_raw(),
        None => {
            throw(&mut env);
            std::ptr::null_mut()
        }
    }
}

/// Returns null when the client rejects the login, like upstream's `undefined`.
#[no_mangle]
pub extern "system" fn Java_org_ruvee_mobile_opaque_OpaqueNative_finishLogin(
    mut env: JNIEnv,
    _class: JClass,
    state: JString,
    response: JString,
    password: JByteArray,
) -> jstring {
    let (Some(state), Some(response), Some(mut pw)) = (
        text(&mut env, &state),
        text(&mut env, &response),
        bytes(&mut env, &password),
    ) else {
        throw(&mut env);
        return std::ptr::null_mut();
    };
    let result = core::finish_login(&state, &response, &pw);
    pw.zeroize();
    match result {
        Ok(None) => std::ptr::null_mut(),
        Ok(Some(finish)) => match env.new_string(finish) {
            Ok(value) => value.into_raw(),
            Err(_) => {
                throw(&mut env);
                std::ptr::null_mut()
            }
        },
        Err(_) => {
            throw(&mut env);
            std::ptr::null_mut()
        }
    }
}
