import { CallError, messageFor, stepMessageFor } from './client';

describe('popup error text', () => {
  it('names the failing call and its code when there are no words for the code', () => {
    expect(stepMessageFor('pendingSave', new CallError('internal'))).toBe(
      'Something went wrong. Try again. (pendingSave: internal)',
    );
    expect(stepMessageFor('sync', new Error('boom'))).toBe(
      'Something went wrong. Try again. (sync: internal)',
    );
  });

  it('keeps the plain message for a code it knows', () => {
    expect(stepMessageFor('sync', new CallError('offline'))).toBe(
      messageFor(new CallError('offline')),
    );
  });
});
