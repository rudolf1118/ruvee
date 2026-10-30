import type { PipeTransform } from '@nestjs/common';
import {
  ISSUE_PATH_SEGMENT_PATTERN,
  MAX_ISSUE_PATH_DEPTH,
  MAX_VALIDATION_ISSUES,
  type ValidationIssue,
} from '@ruvee/contracts';
import type { z } from 'zod';
import { ApiException } from './api-exception.js';

const ISSUE_CODES: Partial<Record<z.core.$ZodIssue['code'], ValidationIssue['code']>> = {
  invalid_type: 'invalid_type',
  too_small: 'too_small',
  too_big: 'too_big',
  invalid_format: 'invalid_format',
  invalid_value: 'invalid_value',
  unrecognized_keys: 'unknown_field',
};

/**
 * Keeps the path up to the first segment that is not a plain field name or
 * index. Zod's own messages, received values and unknown key names are
 * dropped, because they can repeat request input.
 */
export function toValidationIssues(issues: readonly z.core.$ZodIssue[]): ValidationIssue[] {
  return issues.slice(0, MAX_VALIDATION_ISSUES).map((issue) => {
    const path: ValidationIssue['path'] = [];
    for (const segment of issue.path.slice(0, MAX_ISSUE_PATH_DEPTH)) {
      if (typeof segment === 'number' && Number.isSafeInteger(segment) && segment >= 0) {
        path.push(segment);
      } else if (typeof segment === 'string' && ISSUE_PATH_SEGMENT_PATTERN.test(segment)) {
        path.push(segment);
      } else {
        break;
      }
    }
    return { path, code: ISSUE_CODES[issue.code] ?? 'invalid' };
  });
}

/**
 * Validates a request part against a contract schema, for example
 * `@Body(new ContractValidationPipe(schema))`. Request schemas must be strict
 * objects and must not use records or maps, whose keys come from the request.
 */
export class ContractValidationPipe<S extends z.ZodType> implements PipeTransform<
  unknown,
  z.output<S>
> {
  constructor(private readonly schema: S) {}

  transform(value: unknown): z.output<S> {
    const result = this.schema.safeParse(value);
    if (result.success) return result.data;
    throw new ApiException('invalid_request', {
      issues: toValidationIssues(result.error.issues),
    });
  }
}
