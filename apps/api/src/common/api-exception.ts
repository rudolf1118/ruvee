import { HttpException } from '@nestjs/common';
import { API_ERRORS, type ApiErrorCode, type ValidationDetails } from '@ruvee/contracts';

/** An error with a code from the contract list. The exception filter renders it. */
export class ApiException extends HttpException {
  constructor(
    readonly code: ApiErrorCode,
    readonly details?: ValidationDetails,
  ) {
    super(code, API_ERRORS[code].status);
  }
}
