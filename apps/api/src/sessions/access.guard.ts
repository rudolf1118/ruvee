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

/**
 * Global guard. In order: the handler must declare an access level (fail closed); API requests
 * must not carry a bearer token yet (token clients are Phase 5, and cookie plus bearer is always
 * refused); state-changing API requests must pass the CSRF checks of authentication.md §6; then
 * the session level is enforced.
 */
@Injectable()
export class AccessGuard implements CanActivate {
  private readonly publicOrigin: string;

  constructor(
    private readonly reflector: Reflector,
    private readonly sessions: SessionService,
    config: ConfigService<Env, true>,
  ) {
    this.publicOrigin = config.get('PUBLIC_ORIGIN', { infer: true });
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const level = this.reflector.getAllAndOverride<AccessLevel | undefined>(ACCESS_METADATA, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (level === undefined) throw new ApiException('internal_error');

    const req = context.switchToHttp().getRequest<RequestWithSession>();
    if (req.path.startsWith('/api/')) {
      if (req.headers.authorization !== undefined) {
        throw new ApiException(
          readCookie(req, this.sessions.cookieName) === undefined
            ? 'unauthenticated'
            : 'invalid_request',
        );
      }
      if (!SAFE_METHODS.has(req.method)) {
        if (
          req.headers.origin !== this.publicOrigin ||
          req.headers[CSRF_HEADER] !== CSRF_HEADER_VALUE
        )
          throw new ApiException('csrf_rejected');
      }
    }
    if (level === 'none') return true;

    const session = await this.sessions.authenticate(readCookie(req, this.sessions.cookieName));
    if (level !== 'session' && session.deviceStatus !== 'active')
      throw new ApiException('device_not_enrolled');
    if (level === 'step-up' && Date.now() - session.authAt.getTime() > STEP_UP_MS)
      throw new ApiException('step_up_required');
    req.ruveeSession = session;
    return true;
  }
}
