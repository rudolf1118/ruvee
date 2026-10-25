import { type CanActivate, type ExecutionContext, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { CSRF_HEADER, CSRF_HEADER_VALUE } from '@ruvee/contracts';
import { ApiException } from '../common/api-exception.js';
import type { Env } from '../config/env.js';
import { ACCESS_METADATA, type AccessLevel, type RequestWithSession } from './access.decorator.js';
import { readCookie } from './client-info.js';
import { SessionService, STEP_UP_MS } from './session.service.js';

const SAFE_METHODS = new Set(['GET', 'HEAD']);

const BEARER = /^Bearer ([A-Za-z0-9_-]{43})$/;

/**
 * Global guard. In order: the handler must declare an access level (fail closed); a request
 * carries either the session cookie or a bearer token, never both; cookie requests that change
 * state must pass the CSRF checks of authentication.md §6 (bearer requests carry no ambient
 * credential, so CSRF does not apply); then the session level is enforced. Recovery is
 * cookie-only.
 */
@Injectable()
export class AccessGuard implements CanActivate {
  private readonly publicOrigin: string;
  private readonly extensionOrigins: ReadonlySet<string>;

  constructor(
    private readonly reflector: Reflector,
    private readonly sessions: SessionService,
    config: ConfigService<Env, true>,
  ) {
    this.publicOrigin = config.get('PUBLIC_ORIGIN', { infer: true });
    this.extensionOrigins = new Set(
      (config.get('EXTENSION_ORIGINS', { infer: true }) ?? '').split(',').filter(Boolean),
    );
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const level = this.reflector.getAllAndOverride<AccessLevel | undefined>(ACCESS_METADATA, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (level === undefined) throw new ApiException('internal_error');

    const req = context.switchToHttp().getRequest<RequestWithSession>();
    let bearer: string | undefined;
    if (req.path.startsWith('/api/')) {
      if (req.headers.authorization !== undefined) {
        if (readCookie(req, this.sessions.cookieName) !== undefined)
          throw new ApiException('invalid_request');
        bearer = BEARER.exec(req.headers.authorization)?.[1];
        if (bearer === undefined) throw new ApiException('unauthenticated');
      } else if (!SAFE_METHODS.has(req.method)) {
        // A listed extension may call the unauthenticated endpoints, but never with a cookie:
        // it fetches with `credentials: 'omit'`, so a cookie here means someone else's request.
        const cookie =
          readCookie(req, this.sessions.cookieName) ??
          readCookie(req, this.sessions.recoveryCookieName);
        const origin = req.headers.origin;
        const originOk =
          origin === this.publicOrigin ||
          (cookie === undefined &&
            level === 'none' &&
            origin !== undefined &&
            this.extensionOrigins.has(origin));
        if (!originOk || req.headers[CSRF_HEADER] !== CSRF_HEADER_VALUE)
          throw new ApiException('csrf_rejected');
      }
    }
    if (level === 'none') return true;
    if (level === 'recovery') {
      if (!req.path.startsWith('/api/v1/recovery/')) throw new ApiException('internal_error');
      if (bearer !== undefined) throw new ApiException('unauthenticated');
      req.ruveeSession = await this.sessions.authenticateRecovery(
        readCookie(req, this.sessions.recoveryCookieName),
      );
      return true;
    }

    const session =
      bearer === undefined
        ? await this.sessions.authenticate(readCookie(req, this.sessions.cookieName))
        : await this.sessions.authenticate(bearer, new Date(), 'token');
    if (level !== 'session' && session.deviceStatus !== 'active')
      throw new ApiException('device_not_enrolled');
    if (level === 'step-up' && Date.now() - session.authAt.getTime() > STEP_UP_MS)
      throw new ApiException('step_up_required');
    req.ruveeSession = session;
    return true;
  }
}
