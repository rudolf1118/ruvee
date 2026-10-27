// Cross-implementation check of the mobile OPAQUE binding (native/opaque, built for the host)
// against @serenity-kit/opaque 1.1.0, the library the API server and the web client run. It is
// the acceptance test of docs/security/authentication.md §2.3, on the host:
//
// 1. a record registered by the binding logs in through the binding, with the server half on
//    @serenity-kit/opaque;
// 2. a record registered by @serenity-kit/opaque's client (the web) logs in through the binding;
// 3. a record registered by the binding logs in through @serenity-kit/opaque's client;
// 4. a wrong password, a substituted server setup and a tampered response are rejected by the
//    binding (`REJECTED`), and the server refuses a finalization from the wrong password.
//
// Run: node scripts/opaque-interop.mjs   (after `cargo build --release --example interop`)
// Synthetic passwords only.

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import * as opaque from '@serenity-kit/opaque';

const KSF = 'memory-constrained';
const bin = fileURLToPath(
  new URL('../native/opaque/target/release/examples/interop', import.meta.url),
);
const child = spawn(bin, [], { stdio: ['pipe', 'pipe', 'inherit'] });
const lines = createInterface({ input: child.stdout });
const waiting = [];
lines.on('line', (line) => waiting.shift()?.(line));
const ask = (...fields) =>
  new Promise((resolve) => {
    waiting.push(resolve);
    child.stdin.write(`${fields.join('\t')}\n`);
  });
const b64 = (text) => Buffer.from(text, 'utf8').toString('base64url');

await opaque.ready;
const serverSetup = opaque.server.createSetup();
const userIdentifier = 'synthetic-interop@example.test';
const passwords = [
  'synthetic interop lantern 58',
  // NFC text outside ASCII and outside the BMP: the bytes must be the same UTF-8 on both sides.
  'synthétique \u{1f511} 漢字 lantern',
];
const results = [];
const check = (name, ok) => {
  results.push({ name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
};

async function bindingRegister(password) {
  const [state, request] = (await ask('start-registration', b64(password))).split('\t');
  const { registrationResponse } = opaque.server.createRegistrationResponse({
    serverSetup,
    userIdentifier,
    registrationRequest: request,
  });
  return ask('finish-registration', state, registrationResponse, b64(password));
}

function webRegister(password) {
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
    password,
  });
  const { registrationResponse } = opaque.server.createRegistrationResponse({
    serverSetup,
    userIdentifier,
    registrationRequest,
  });
  return opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse,
    password,
    keyStretching: KSF,
  }).registrationRecord;
}

/** Binding client, @serenity-kit/opaque server. Returns whether the server accepted the login. */
async function bindingLogin(record, password, setup = serverSetup, tamper = false) {
  const [state, request] = (await ask('start-login', b64(password))).split('\t');
  const server = opaque.server.startLogin({
    serverSetup: setup,
    userIdentifier,
    registrationRecord: record,
    startLoginRequest: request,
  });
  let response = server.loginResponse;
  if (tamper) {
    const bytes = Buffer.from(response, 'base64url');
    bytes[bytes.length - 1] ^= 1;
    response = bytes.toString('base64url');
  }
  const finish = await ask('finish-login', state, response, b64(password));
  if (finish === 'REJECTED' || finish === 'ERROR') return finish;
  try {
    opaque.server.finishLogin({
      finishLoginRequest: finish,
      serverLoginState: server.serverLoginState,
    });
    return 'ACCEPTED';
  } catch {
    return 'SERVER_REFUSED';
  }
}

function webLogin(record, password) {
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
  const server = opaque.server.startLogin({
    serverSetup,
    userIdentifier,
    registrationRecord: record,
    startLoginRequest,
  });
  const finished = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: server.loginResponse,
    password,
    keyStretching: KSF,
  });
  if (!finished) return 'REJECTED';
  const { sessionKey } = opaque.server.finishLogin({
    finishLoginRequest: finished.finishLoginRequest,
    serverLoginState: server.serverLoginState,
  });
  return sessionKey === finished.sessionKey ? 'ACCEPTED' : 'KEY_MISMATCH';
}

for (const [i, password] of passwords.entries()) {
  const fromBinding = await bindingRegister(password);
  check(
    `${i}: binding registers, binding logs in`,
    (await bindingLogin(fromBinding, password)) === 'ACCEPTED',
  );
  check(
    `${i}: binding registers, web client logs in`,
    webLogin(fromBinding, password) === 'ACCEPTED',
  );
  const fromWeb = webRegister(password);
  check(
    `${i}: web registers, binding logs in`,
    (await bindingLogin(fromWeb, password)) === 'ACCEPTED',
  );
  check(
    `${i}: wrong password rejected by the binding`,
    (await bindingLogin(fromWeb, `${password}!`)) === 'REJECTED',
  );
  check(
    `${i}: substituted server setup rejected by the binding`,
    (await bindingLogin(fromWeb, password, opaque.server.createSetup())) === 'REJECTED',
  );
  check(
    `${i}: tampered login response rejected`,
    ['REJECTED', 'ERROR'].includes(await bindingLogin(fromWeb, password, serverSetup, true)),
  );
}
check(
  'malformed input is an error, not a login',
  (await ask('finish-login', '!!', '!!', b64('x'))) === 'ERROR',
);

child.stdin.end();
const failed = results.filter((r) => !r.ok).length;
console.log(`${results.length} checks, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
