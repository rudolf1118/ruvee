import { randomUUID } from 'node:crypto';
import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  Logger,
} from '@nestjs/common';
import {
  API_ERRORS,
  type ApiErrorCode,
  type ErrorResponse,
  REQUEST_ID_HEADER,
  REQUEST_ID_PATTERN,
} from '@ruvee/contracts';
import type { Request, Response } from 'express';
import { ApiException } from './api-exception.js';

/** Framework exceptions that map onto a contract code. Any other status is an internal error. */
const CODES_BY_STATUS: Partial<Record<number, ApiErrorCode>> = {
  400: 'invalid_request',
  404: 'not_found',
  413: 'payload_too_large',
  415: 'unsupported_media_type',
};

const MAX_LOGGED_FRAMES = 20;

/**
 * The stack without its first line, which repeats the message. Messages are
 * never logged, because they can contain request input or connection strings.
 */
export function stackFrames(error: Error): string[] {
  const header = `${String(error)}\n`;
  if (typeof error.stack !== 'string' || !error.stack.startsWith(header)) return [];
  return error.stack
    .slice(header.length)
    .split('\n')
    .slice(0, MAX_LOGGED_FRAMES)
    .map((line) => line.trim());
}

export function describeError(error: unknown): { errorKind: string; frames: string[] } {
  if (!(error instanceof Error)) return { errorKind: typeof error, frames: [] };
  return { errorKind: error.name.slice(0, 64), frames: stackFrames(error) };
}

export function errorResponse(
  code: ApiErrorCode,
  requestId: string,
  details?: unknown,
): ErrorResponse {
  const { status, message } = API_ERRORS[code];
  const body = { statusCode: status, error: code, message, requestId };
  return (details === undefined ? body : { ...body, details }) as ErrorResponse;
}

/**
 * Renders every error in the contract shape with a fixed message per code.
 * Unexpected errors become `500 internal_error`; only their class and stack
 * frames are logged.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const req = http.getRequest<Request & { id?: unknown }>();
    const res = http.getResponse<Response>();

    const { code, details } = this.classify(exception);

    if (res.headersSent) return;
    const retryAfter =
      exception instanceof ApiException ? (exception as ApiException).retryAfterSeconds : undefined;
    if (retryAfter !== undefined)
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil(retryAfter))));
    let requestId = req.id;
    if (typeof requestId !== 'string' || !REQUEST_ID_PATTERN.test(requestId)) {
      requestId = randomUUID();
      res.setHeader(REQUEST_ID_HEADER, requestId);
    }
    res.status(API_ERRORS[code].status).json(errorResponse(code, requestId, details));
  }

  private classify(exception: unknown): { code: ApiErrorCode; details?: unknown } {
    if (exception instanceof ApiException) {
      const { code, details } = exception as ApiException;
      if (code === 'internal_error') {
        this.logger.error(describeError(exception), 'Internal error');
      }
      return details === undefined ? { code } : { code, details: details };
    }
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const code = CODES_BY_STATUS[status];
      if (code) return { code };
      this.logger.error({ status, ...describeError(exception) }, 'Unmapped HTTP exception');
      return { code: 'internal_error' };
    }
    this.logger.error(describeError(exception), 'Unhandled exception');
    return { code: 'internal_error' };
  }
}
