import { HttpException } from '@nestjs/common';
import { API_ERRORS, type ApiErrorCode, type ErrorDetails } from '@ruvee/contracts';

type DetailsFor<C extends ApiErrorCode> = C extends keyof ErrorDetails ? ErrorDetails[C] : never;

/** An error with a code from the contract list. The exception filter renders it. */
export class ApiException<C extends ApiErrorCode = ApiErrorCode> extends HttpException {
  constructor(
    readonly code: C,
    readonly details?: DetailsFor<C>,
    /** Sent as `Retry-After` with `rate_limited`. */
    readonly retryAfterSeconds?: number,
  ) {
    super(code, API_ERRORS[code].status);
  }
}
