import { SetMetadata } from '@nestjs/common';

/**
 * What a controller is, for the decisions the global guard makes before authentication
 * (predeployment-review R1). Decided by the matched handler, never by URL text, so no spelling of
 * a path can change it. A controller that declares nothing is `api`: the default, most
 * restricted class.
 * - `api`: the authenticated API; closed in every restore state but `open`
 * - `recovery`: /recovery/*; the only class that accepts the `recovery` access level
 * - `reopen`: /reopen/*; the only class served while reopening, and the only one that accepts
 *   the `reopen` access level
 * - `health`: liveness and readiness; served in every state, never authenticated
 */
export type RouteClass = 'api' | 'recovery' | 'reopen' | 'health';

export const ROUTE_CLASS_METADATA = 'ruvee:route-class';

export const RouteClassOf = (routeClass: RouteClass) =>
  SetMetadata(ROUTE_CLASS_METADATA, routeClass);
