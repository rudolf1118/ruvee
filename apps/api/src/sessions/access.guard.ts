import { type CanActivate, type ExecutionContext, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { CSRF_HEADER, CSRF_HEADER_VALUE } from '@ruvee/contracts';
import { ThrottleService } from '../auth/throttle.service.js';
import { ApiException } from '../common/api-exception.js';
import type { Env } from '../config/env.js';
import {
  ACCESS_METADATA,
  BEFORE_PROOF_METADATA,
  EXTENSION_METADATA,
  type AccessLevel,
  type RequestWithSession,
} from './access.decorator.js';
import { readCookie } from './client-info.js';
import { InstanceLockService } from '../database/instance-lock.service.js';
import { MaintenanceService } from '../maintenance/maintenance.service.js';
import { ROUTE_CLASS_METADATA, type RouteClass } from './route-class.js';
import { SessionService, STEP_UP_MS } from './session.service.js';

const SAFE_METHODS = new Set(['GET', 'HEAD']);

const BEARER = /^Bearer ([A-Za-z0-9_-]{43})$/;

const PROXY_HINT =
  'every client is limited as the one address of the reverse proxy. Set it to that address (authentication.md §7).';
const PROXY_UNSET_IN_PRODUCTION = `NODE_ENV is production and TRUSTED_PROXY_ADDRESS is not set: behind a reverse proxy, ${PROXY_HINT}`;
const FORWARDED_WITHOUT_PROXY = `A request carried X-Forwarded-For, but TRUSTED_PROXY_ADDRESS is not set: ${PROXY_HINT}`;

/**
 * Global guard. In order: the handler must declare an access level (fail closed); a request
 * carries either a cookie or a bearer token, never both; requests that change state must pass the
 * CSRF checks of authentication.md §6, except where a bearer token is the credential (it is not
 * ambient, so CSRF does not apply); then the session level is enforced. Recovery is cookie-only.
 */
@Injectable()
export class AccessGuard implements CanActivate {
  private readonly publicOrigin: string;
  private readonly extensionOrigins: ReadonlySet<string>;
  private readonly logger = new Logger('ClientAddress');
  private readonly proxyConfigured: boolean;
  private warnedAboutProxy = false;

  constructor(
    private readonly reflector: Reflector,
    private readonly sessions: SessionService,
    private readonly maintenance: MaintenanceService,
    private readonly throttle: ThrottleService,
    private readonly instance: InstanceLockService,
    config: ConfigService<Env, true>,
  ) {
    this.publicOrigin = config.get('PUBLIC_ORIGIN', { infer: true });
    this.extensionOrigins = new Set(
      (config.get('EXTENSION_ORIGINS', { infer: true }) ?? '').split(',').filter(Boolean),
    );
    this.proxyConfigured = config.get('TRUSTED_PROXY_ADDRESS', { infer: true }) !== undefined;
    if (!this.proxyConfigured && config.get('NODE_ENV', { infer: true }) === 'production')
      this.logger.warn(PROXY_UNSET_IN_PRODUCTION);
  }

  /**
   * Review R17: behind a reverse proxy with no TRUSTED_PROXY_ADDRESS, every client has the
   * proxy's address, so one client can use up everyone's per-address limits. A forwarded header
   * with no trusted proxy is the sign of that; it is said once, without the header's value.
   */
  private noticeForwarding(req: RequestWithSession): void {
    if (this.proxyConfigured || this.warnedAboutProxy) return;
    if (req.headers['x-forwarded-for'] === undefined) return;
    this.warnedAboutProxy = true;
    this.logger.warn(FORWARDED_WITHOUT_PROXY);
  }

  /** Every authenticated request counts against its session's per-minute limit (review R16). */
  private limited<T extends { sessionId: string }>(session: T): T {
    this.throttle.assertSessionAllowed(session.sessionId);
    return session;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const level = this.reflector.getAllAndOverride<AccessLevel | undefined>(ACCESS_METADATA, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (level === undefined) throw new ApiException('internal_error');

    const routeClass =
      this.reflector.getAllAndOverride<RouteClass | undefined>(ROUTE_CLASS_METADATA, [
        context.getHandler(),
        context.getClass(),
      ]) ?? 'api';
    const req = context.switchToHttp().getRequest<RequestWithSession>();
    this.noticeForwarding(req);
    // Only the one process holding the instance lock serves (V1: one API process per database).
    if (routeClass !== 'health') this.instance.assertServing();
    // A restored installation in review serves nothing at all, whatever the credentials, and
    // while it waits to be reopened only the reopening endpoints: restored cookies, tokens and
    // passwords cannot open it (backup-restore.md §3.6 rules 3, 4; §3.13). Decided by the matched
    // handler, not the URL (predeployment-review R1).
    await this.maintenance.gate(routeClass);
    if (routeClass === 'health') {
      if (level !== 'none') throw new ApiException('internal_error');
      return true;
    }
    // Every other route: the cookie-xor-bearer rule and the CSRF checks apply, whatever its path.
    // Any of the three cookies counts: a request never carries a cookie and a bearer token.
    const cookie =
      readCookie(req, this.sessions.cookieName) ??
      readCookie(req, this.sessions.recoveryCookieName) ??
      readCookie(req, this.sessions.reopenCookieName);
    let bearer: string | undefined;
    if (req.headers.authorization !== undefined) {
      if (cookie !== undefined) throw new ApiException('invalid_request');
      bearer = BEARER.exec(req.headers.authorization)?.[1];
      if (bearer === undefined) throw new ApiException('unauthenticated');
    }
    // A bearer request skips CSRF only where that token is the credential checked below. An
    // unauthenticated, recovery or reopen route never reads it, so a header of any value must not
    // exempt the request (follow-up review F-6).
    const authenticatesBearer =
      bearer !== undefined && (level === 'session' || level === 'active' || level === 'step-up');
    if (!authenticatesBearer && !SAFE_METHODS.has(req.method)) {
      // A listed extension may call the unauthenticated endpoints it uses (login and refresh,
      // marked on the handler; review R23), but never with a cookie: it fetches with
      // `credentials: 'omit'`, so a cookie here means someone else's request.
      const origin = req.headers.origin;
      const originOk =
        origin === this.publicOrigin ||
        (cookie === undefined &&
          level === 'none' &&
          origin !== undefined &&
          this.extensionOrigins.has(origin) &&
          this.reflector.getAllAndOverride<boolean | undefined>(EXTENSION_METADATA, [
            context.getHandler(),
            context.getClass(),
          ]) === true);
      if (!originOk || req.headers[CSRF_HEADER] !== CSRF_HEADER_VALUE)
        throw new ApiException('csrf_rejected');
    }
    if (level === 'none') return true;
    if (level === 'recovery') {
      if (routeClass !== 'recovery') throw new ApiException('internal_error');
      if (bearer !== undefined) throw new ApiException('unauthenticated');
      req.ruveeSession = this.limited(
        await this.sessions.authenticateRecovery(readCookie(req, this.sessions.recoveryCookieName)),
      );
      return true;
    }
    // The recovery and reopen controllers accept only their own session kinds.
    if (routeClass === 'recovery' || (routeClass === 'reopen' && level !== 'reopen'))
      throw new ApiException('internal_error');

    if (level === 'reopen') {
      // Only the reopening endpoints, only with the reopen cookie: never a bearer token, and a
      // reopen session is never accepted anywhere else (backup-restore.md §3.13).
      if (routeClass !== 'reopen') throw new ApiException('internal_error');
      if (bearer !== undefined) throw new ApiException('unauthenticated');
      req.ruveeSession = this.limited(
        await this.sessions.authenticateReopen(readCookie(req, this.sessions.reopenCookieName)),
      );
      return true;
    }

    const session = this.limited(
      bearer === undefined
        ? await this.sessions.authenticate(readCookie(req, this.sessions.cookieName))
        : await this.sessions.authenticate(bearer, new Date(), 'token'),
    );
    // device-proof.md §5 and §7: an active device acts as itself only after proving its key.
    // The password alone reaches the five allowlisted handlers and nothing else (R2).
    if (session.deviceStatus === 'active' && !session.proven) {
      const allowed = this.reflector.getAllAndOverride<boolean | undefined>(BEFORE_PROOF_METADATA, [
        context.getHandler(),
        context.getClass(),
      ]);
      if (allowed !== true) throw new ApiException('device_proof_required');
    }
    if (level !== 'session' && session.deviceStatus !== 'active')
      throw new ApiException('device_not_enrolled');
    if (level === 'step-up' && Date.now() - session.authAt.getTime() > STEP_UP_MS)
      throw new ApiException('step_up_required');
    req.ruveeSession = session;
    return true;
  }
}
