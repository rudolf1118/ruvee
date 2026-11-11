import { normalizePassword } from '@ruvee/crypto';
import * as opaque from '@serenity-kit/opaque';
import { evalIsBlocked, type ProbeResult } from './probe-result';

/**
 * P2-04 diagnostic: `@serenity-kit/opaque` 1.1.0 in a dedicated worker under the production CSP.
 * Both protocol sides run here with synthetic inputs, because the spike tests the library under
 * the CSP, not the API. This is not Ruvee's authentication implementation and approves nothing.
 */

const KEY_STRETCHING = 'memory-constrained' as const;
const USERNAME = 'synthetic-probe-user';
// Synthetic. The NFD form below must log in against a registration made with the NFC form.
const PASSWORD_NFC = 'synthetic café probe passphrase';
const PASSWORD_NFD = 'synthetic café probe passphrase';
const WRONG_PASSWORD = 'synthetic wrong probe passphrase';

function register(serverSetup: string, password: string): string {
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
    password,
  });
  const { registrationResponse } = opaque.server.createRegistrationResponse({
    serverSetup,
    userIdentifier: USERNAME,
    registrationRequest,
  });
  return opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse,
    password,
    keyStretching: KEY_STRETCHING,
  }).registrationRecord;
}

interface LoginAttempt {
  readonly clientAccepted: boolean;
  readonly serverAccepted: boolean;
  readonly sessionKeysMatch: boolean;
  readonly loginResponseLength: number;
}

function login(
  serverSetup: string,
  registrationRecord: string | null,
  password: string,
): LoginAttempt {
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
  const { serverLoginState, loginResponse } = opaque.server.startLogin({
    serverSetup,
    registrationRecord,
    startLoginRequest,
    userIdentifier: USERNAME,
  });
  const client = opaque.client.finishLogin({
    clientLoginState,
    loginResponse,
    password,
    keyStretching: KEY_STRETCHING,
  });
  if (client === undefined) {
    return {
      clientAccepted: false,
      serverAccepted: false,
      sessionKeysMatch: false,
      loginResponseLength: loginResponse.length,
    };
  }
  const server = opaque.server.finishLogin({
    serverLoginState,
    finishLoginRequest: client.finishLoginRequest,
  });
  return {
    clientAccepted: true,
    serverAccepted: true,
    sessionKeysMatch: server.sessionKey === client.sessionKey,
    loginResponseLength: loginResponse.length,
  };
}

export interface OpaqueChecks {
  readonly correctPassword: LoginAttempt;
  readonly nfdTypedPassword: LoginAttempt;
  readonly wrongPassword: LoginAttempt;
  readonly unknownUser: LoginAttempt;
  readonly substitutedServerSetup: LoginAttempt;
  readonly elapsedMs: number;
}

async function run(): Promise<OpaqueChecks> {
  await opaque.ready;
  const started = performance.now();
  const serverSetup = opaque.server.createSetup();
  const record = register(serverSetup, normalizePassword(PASSWORD_NFC));
  return {
    correctPassword: login(serverSetup, record, normalizePassword(PASSWORD_NFC)),
    nfdTypedPassword: login(serverSetup, record, normalizePassword(PASSWORD_NFD)),
    wrongPassword: login(serverSetup, record, normalizePassword(WRONG_PASSWORD)),
    unknownUser: login(serverSetup, null, normalizePassword(PASSWORD_NFC)),
    substitutedServerSetup: login(
      opaque.server.createSetup(),
      record,
      normalizePassword(PASSWORD_NFC),
    ),
    elapsedMs: Math.round(performance.now() - started),
  };
}

self.onmessage = () => {
  const evalBlocked = evalIsBlocked();
  void run().then(
    (checks) => {
      const ok =
        checks.correctPassword.sessionKeysMatch &&
        checks.nfdTypedPassword.sessionKeysMatch &&
        !checks.wrongPassword.clientAccepted &&
        !checks.unknownUser.clientAccepted &&
        !checks.substitutedServerSetup.clientAccepted &&
        checks.unknownUser.loginResponseLength === checks.correctPassword.loginResponseLength;
      const result: ProbeResult<OpaqueChecks> = { ok, evalBlocked, details: checks };
      self.postMessage(result);
    },
    (error: unknown) => {
      const result: ProbeResult<OpaqueChecks> = {
        ok: false,
        evalBlocked,
        error: error instanceof Error ? error.message : 'opaque probe failed',
      };
      self.postMessage(result);
    },
  );
};
