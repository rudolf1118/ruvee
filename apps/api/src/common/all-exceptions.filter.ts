import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';

export interface ErrorResponseBody {
  statusCode: number;
  error: string;
  message: string;
  requestId?: string;
}

function messageFrom(exception: HttpException): string {
  const response = exception.getResponse();
  if (typeof response === 'string') return response;
  const message = (response as { message?: unknown }).message;
  if (Array.isArray(message)) return message.map(String).join('; ');
  return typeof message === 'string' ? message : exception.message;
}

/**
 * Renders every error with one JSON shape. Unexpected errors are logged in
 * full on the server but only reported to clients as a generic 500.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const req = http.getRequest<Request & { id?: string }>();
    const res = http.getResponse<Response>();

    let body: ErrorResponseBody;
    if (exception instanceof HttpException) {
      const statusCode = exception.getStatus();
      body = {
        statusCode,
        error: HttpStatus[statusCode] ?? 'ERROR',
        message: messageFrom(exception),
      };
      if (statusCode >= 500) this.logger.error({ err: exception }, 'HTTP exception');
    } else {
      body = {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Internal server error',
      };
      this.logger.error({ err: exception }, 'Unhandled exception');
    }
    if (req.id) body.requestId = req.id;

    if (res.headersSent) return;
    res.status(body.statusCode).json(body);
  }
}
