//! Host-only helper for scripts/opaque-interop.mjs: runs this crate's client operations on lines
//! from stdin and answers on stdout. Fields are tab-separated; the password is base64url so any
//! UTF-8 survives. Synthetic data only; never built into the app.
//!
//!   start-registration <password>                  -> <state> <request>
//!   finish-registration <state> <response> <password> -> <record>
//!   start-login <password>                          -> <state> <request>
//!   finish-login <state> <response> <password>      -> <finishLoginRequest> | REJECTED

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use ruvee_opaque::core;
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split('\t').collect();
        let pw = |s: &str| B64.decode(s).expect("password base64");
        let answer = match f.as_slice() {
            ["start-registration", p] => core::start_registration(&pw(p))
                .map(|s| format!("{}\t{}", s.state, s.request)),
            ["finish-registration", s, r, p] => core::finish_registration(s, r, &pw(p)),
            ["start-login", p] => core::start_login(&pw(p)).map(|s| format!("{}\t{}", s.state, s.request)),
            ["finish-login", s, r, p] => {
                core::finish_login(s, r, &pw(p)).map(|v| v.unwrap_or_else(|| "REJECTED".into()))
            }
            _ => Err(core::OpaqueError),
        };
        writeln!(out, "{}", answer.unwrap_or_else(|_| "ERROR".into())).expect("stdout");
        out.flush().expect("flush");
    }
}
