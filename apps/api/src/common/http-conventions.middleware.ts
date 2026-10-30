import { Injectable, type NestMiddleware } from '@nestjs/common';
import { JSON_MEDIA_TYPE, MAX_COMMIT_BODY_BYTES, MAX_REQUEST_BODY_BYTES } from '@ruvee/contracts';
import express, { type NextFunction, type Request, type Response } from 'express';
import { ApiException } from './api-exception.js';

const METHODS_WITH_BODY = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const jsonParser = (limit: number) =>
  express.json({
    limit,
    // Compressed bodies are refused, so the limit is the number of bytes actually received.
    inflate: false,
    strict: true,
    // The media type was already checked, more strictly than body-parser would.
    type: () => true,
  });

const parseJson = jsonParser(MAX_REQUEST_BODY_BYTES);
/** Sync commits carry up to 2 MiB of records (sync-protocol §4.2); every other route keeps 64 KiB. */
const parseCommitJson = jsonParser(MAX_COMMIT_BODY_BYTES);
export const COMMIT_PATH = '/api/v1/sync/commits';

export function hasBody(req: Request): boolean {
  const length = req.headers['content-length'];
  return req.headers['transfer-encoding'] !== undefined || (length !== undefined && length !== '0');
}

/** `application/json`, optionally with `charset=utf-8`, and no other parameter. */
export function isJsonContentType(header: string | undefined): boolean {
  if (header === undefined) return false;
  const [type, ...params] = header.split(';').map((part) => part.trim().toLowerCase());
  if (type !== JSON_MEDIA_TYPE) return false;
  return params.every((param) => param === 'charset=utf-8' || param === 'charset="utf-8"');
}

/**
 * Body-parser errors can carry the raw body and parser messages that quote it,
 * so they are replaced, never forwarded.
 */
export function fromBodyParserError(error: unknown): ApiException | Error {
  const { type, status } = (error ?? {}) as { type?: unknown; status?: unknown };
  switch (type) {
    case 'entity.parse.failed':
      return new ApiException('malformed_json');
    case 'entity.too.large':
      return new ApiException('payload_too_large');
    case 'charset.unsupported':
    case 'encoding.unsupported':
      return new ApiException('unsupported_media_type');
    default:
      if (typeof status === 'number' && status >= 400 && status < 500) {
        return new ApiException('invalid_request');
      }
      return new Error('The request body could not be read');
  }
}

/**
 * Applies the transport conventions to every request: responses are never
 * cached, and bodies are parsed only as size-limited UTF-8 JSON. Registered
 * after the request logger, so rejected bodies still get a request id and an
 * access log line.
 */
@Injectable()
export class HttpConventionsMiddleware implements NestMiddleware<Request, Response> {
  use(req: Request, res: Response, next: NextFunction): void {
    res.setHeader('Cache-Control', 'no-store');
    if (!METHODS_WITH_BODY.has(req.method) || !hasBody(req)) {
      next();
      return;
    }
    if (!isJsonContentType(req.headers['content-type'])) {
      next(new ApiException('unsupported_media_type'));
      return;
    }
    const parse = req.method === 'POST' && req.path === COMMIT_PATH ? parseCommitJson : parseJson;
    parse(req, res, (error?: unknown) => {
      if (error === undefined) next();
      else next(fromBodyParserError(error));
    });
  }
}
