import { readFileSync, statSync } from 'node:fs';
import { Injectable, type OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as opaque from '@serenity-kit/opaque';
import type { Env } from '../config/env.js';

/** 128 bytes in unpadded base64url, as `@serenity-kit/opaque` 1.1.0 writes it. */
const SETUP_PATTERN = /^[A-Za-z0-9_-]{171}$/;

export class OpaqueSetupError extends Error {
  constructor(reason: string) {
    // The reason names the problem; the file content is never part of the message.
    super(`OPAQUE server setup unusable: ${reason}`);
    this.name = 'OpaqueSetupError';
  }
}

/**
 * Reads and checks the OPAQUE server setup file (INV-21). The setup never touches the database
 * or a log line. Every OPAQUE server operation goes through this service, with the fixed
 * configuration of D-02: no server identifier, so `identifiers` is never passed.
 */
export function loadServerSetup(path: string, production: boolean): string {
  let content: string;
  try {
    const stats = statSync(path);
    if (!stats.isFile()) throw new OpaqueSetupError('not a regular file');
    // In production the secret must not be readable by other users of the host.
    if (production && (stats.mode & 0o077) !== 0)
      throw new OpaqueSetupError('file is readable by group or others; use mode 0600');
    content = readFileSync(path, 'utf8').trim();
  } catch (error) {
    if (error instanceof OpaqueSetupError) throw error;
    throw new OpaqueSetupError('file cannot be read');
  }
  if (!SETUP_PATTERN.test(content)) throw new OpaqueSetupError('unexpected format');
  try {
    opaque.server.getPublicKey(content);
  } catch {
    throw new OpaqueSetupError('library rejected it');
  }
  return content;
}

@Injectable()
export class OpaqueServerService implements OnModuleInit {
  private setup: string | undefined;

  constructor(private readonly config: ConfigService<Env, true>) {}

  async onModuleInit(): Promise<void> {
    await opaque.ready;
    this.setup = loadServerSetup(
      this.config.get('OPAQUE_SERVER_SETUP_FILE', { infer: true }),
      this.config.get('NODE_ENV', { infer: true }) === 'production',
    );
  }

  private serverSetup(): string {
    if (this.setup === undefined) throw new Error('OPAQUE server setup not loaded');
    return this.setup;
  }

  createRegistrationResponse(userIdentifier: string, registrationRequest: string): string {
    return opaque.server.createRegistrationResponse({
      serverSetup: this.serverSetup(),
      userIdentifier,
      registrationRequest,
    }).registrationResponse;
  }

  /** `registrationRecord` null produces the simulated response for an unknown user. */
  startLogin(
    userIdentifier: string,
    registrationRecord: string | null,
    startLoginRequest: string,
  ): { serverLoginState: string; loginResponse: string } {
    return opaque.server.startLogin({
      serverSetup: this.serverSetup(),
      registrationRecord,
      startLoginRequest,
      userIdentifier,
    });
  }

  /** True only when the client proved knowledge of the password. Never throws to the caller. */
  finishLogin(serverLoginState: string, finishLoginRequest: string): boolean {
    try {
      const { sessionKey } = opaque.server.finishLogin({ serverLoginState, finishLoginRequest });
      return typeof sessionKey === 'string' && sessionKey.length > 0;
    } catch {
      return false;
    }
  }
}
