import { createParamDecorator, type ExecutionContext, SetMetadata } from '@nestjs/common';
import type { Request } from 'express';
import type { AuthenticatedSession } from './session.service.js';

/**
 * Authentication levels of api-design.md §Authentication levels. Every handler must declare
 * one; the global guard refuses handlers that do not (fail closed).
 * - `none`: no session needed (rate-limited where the flow says so)
 * - `session`: a valid cookie session on a pending or active device
 * - `active`: as `session`, and the device is enrolled
 * - `step-up`: as `active`, and the session authenticated with OPAQUE within 5 minutes
 * - `recovery`: a recovery session (its own cookie); accepted only on /recovery/* endpoints
 */
export type AccessLevel = 'none' | 'session' | 'active' | 'step-up' | 'recovery';

export const ACCESS_METADATA = 'ruvee:access';

export const Access = (level: AccessLevel) => SetMetadata(ACCESS_METADATA, level);

export interface RequestWithSession extends Request {
  ruveeSession?: AuthenticatedSession;
}

/** The session the guard attached; only on handlers whose level is not `none`. */
export const CurrentSession = createParamDecorator((_: unknown, ctx: ExecutionContext) => {
  const session = ctx.switchToHttp().getRequest<RequestWithSession>().ruveeSession;
  if (!session) throw new Error('CurrentSession used on a handler without a session level');
  return session;
});
