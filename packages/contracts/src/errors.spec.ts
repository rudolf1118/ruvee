import {
  API_ERRORS,
  type ApiErrorCode,
  errorResponseSchema,
  MAX_VALIDATION_ISSUES,
} from './errors.js';

const codes = Object.keys(API_ERRORS) as ApiErrorCode[];

function body(code: ApiErrorCode) {
  return {
    statusCode: API_ERRORS[code].status,
    error: code,
    message: API_ERRORS[code].message,
    requestId: 'req-1',
  };
}

describe('error responses', () => {
  it.each(codes)('accepts the fixed body for %s', (code) => {
    expect(errorResponseSchema.safeParse(body(code)).success).toBe(true);
  });

  it('ties each code to its status and message', () => {
    expect(errorResponseSchema.safeParse({ ...body('not_found'), statusCode: 400 }).success).toBe(
      false,
    );
    expect(
      errorResponseSchema.safeParse({ ...body('not_found'), message: 'Cannot GET /secret' })
        .success,
    ).toBe(false);
  });

  it('rejects unknown codes, extra fields and a missing request id', () => {
    expect(errorResponseSchema.safeParse({ ...body('not_found'), error: 'nope' }).success).toBe(
      false,
    );
    expect(errorResponseSchema.safeParse({ ...body('not_found'), stack: 'at x' }).success).toBe(
      false,
    );
    const withoutId: Partial<ReturnType<typeof body>> = body('not_found');
    delete withoutId.requestId;
    expect(errorResponseSchema.safeParse(withoutId).success).toBe(false);
    expect(
      errorResponseSchema.safeParse({ ...body('not_found'), requestId: 'has space' }).success,
    ).toBe(false);
  });

  it('allows details only on invalid_request, with bounded issues', () => {
    const issue = { path: ['label'], code: 'too_big' };
    expect(
      errorResponseSchema.safeParse({ ...body('invalid_request'), details: { issues: [issue] } })
        .success,
    ).toBe(true);
    expect(
      errorResponseSchema.safeParse({ ...body('not_found'), details: { issues: [issue] } }).success,
    ).toBe(false);
    const tooMany = Array.from({ length: MAX_VALIDATION_ISSUES + 1 }, () => issue);
    expect(
      errorResponseSchema.safeParse({ ...body('invalid_request'), details: { issues: tooMany } })
        .success,
    ).toBe(false);
  });

  it('rejects issue paths that could carry request-supplied keys', () => {
    const withPath = (path: unknown[]) => ({
      ...body('invalid_request'),
      details: { issues: [{ path, code: 'invalid' }] },
    });
    expect(errorResponseSchema.safeParse(withPath(['items', 0, 'name'])).success).toBe(true);
    expect(errorResponseSchema.safeParse(withPath(['a b'])).success).toBe(false);
    expect(errorResponseSchema.safeParse(withPath(['x'.repeat(65)])).success).toBe(false);
    expect(errorResponseSchema.safeParse(withPath([-1])).success).toBe(false);
  });
});
