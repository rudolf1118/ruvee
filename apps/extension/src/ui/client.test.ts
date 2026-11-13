import { CallError, messageFor, stepMessageFor } from './client';

describe('popup error text', () => {
  it('names the failing call and its code when there are no words for the code', () => {
    expect(stepMessageFor('sync', new CallError('internal'))).toBe(
      'Something went wrong. Try again. (sync: internal)',
    );
    expect(stepMessageFor('fill', new Error('boom'))).toBe(
      'Something went wrong. Try again. (fill: internal)',
    );
  });

  it('says plainly that an item is gone', () => {
    expect(messageFor(new CallError('not_found'))).toMatch(/no longer in your vault/);
    expect(stepMessageFor('fill', new CallError('not_found'))).toMatch(/no longer in your vault/);
  });
});
