import { PASSWORD_MAX_BYTES } from '@ruvee/crypto';

/**
 * D-09, approved for development: at least 12 characters after NFC, at most 4,096 UTF-8 bytes,
 * no composition rules, and a strength hint. Rejecting common passwords is part of D-09 but
 * needs a reviewed list; it is not implemented yet. The cryptography does not depend on any of
 * this (cryptographic-design §3.1); the policy only protects the user from weak choices.
 */
export const MASTER_PASSWORD_MIN_CHARACTERS = 12;

export type Strength = 'too_short' | 'weak' | 'fair' | 'strong';

export interface PasswordCheck {
  readonly ok: boolean;
  readonly characters: number;
  readonly strength: Strength;
  readonly problem?: 'too_short' | 'too_long' | 'malformed';
}

function isWellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

/**
 * A rough estimate from length and character variety. It is a hint, not a guarantee: it does
 * not know about dictionary words or reuse.
 */
function estimate(normalized: string, characters: number): Strength {
  if (characters < MASTER_PASSWORD_MIN_CHARACTERS) return 'too_short';
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) =>
    r.test(normalized),
  ).length;
  const distinct = new Set(normalized).size;
  if (distinct < 6) return 'weak';
  if (characters >= 20 || (characters >= 16 && classes >= 3)) return 'strong';
  return classes >= 2 ? 'fair' : 'weak';
}

export function checkMasterPassword(password: string): PasswordCheck {
  if (!isWellFormed(password))
    return { ok: false, characters: 0, strength: 'too_short', problem: 'malformed' };
  const normalized = password.normalize('NFC');
  const characters = normalized.match(/./gsu)?.length ?? 0;
  const strength = estimate(normalized, characters);
  if (new TextEncoder().encode(normalized).length > PASSWORD_MAX_BYTES)
    return { ok: false, characters, strength, problem: 'too_long' };
  if (characters < MASTER_PASSWORD_MIN_CHARACTERS)
    return { ok: false, characters, strength, problem: 'too_short' };
  return { ok: true, characters, strength };
}
