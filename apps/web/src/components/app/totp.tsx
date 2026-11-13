'use client';

import { type ClipboardEvent, type DragEvent, useEffect, useMemo, useRef, useState } from 'react';
import {
  CLOCK_SKEW_WARNING_MS,
  parseTotpInput,
  TOTP_INPUT_MAX,
  totpCodes,
  type TotpInputError,
  type Totp,
  type TotpView,
} from '@ruvee/vault';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { decodeQrImage, type QrResult } from '@/vault/qr';
import { Button } from '../ui/button';
import { cx } from '../ui/cx';
import { CopyIcon } from '../ui/icons';
import { copySecret } from './clipboard';
import { FieldError, Notice } from './fields';

/** Authenticator codes in the web vault (D-35, totp-authenticator.md §3 and §5). */

export const TOTP_INPUT_MESSAGES: Record<TotpInputError, string> = {
  empty: 'Paste the setup key or the otpauth:// link the site shows, or add a QR code image.',
  too_long: 'This is too long to be a setup key.',
  not_base32: 'A setup key uses only the letters A to Z and the digits 2 to 7.',
  secret_too_short: 'This setup key is too short. Check that you copied all of it.',
  secret_too_long: 'This setup key is longer than any site uses. Check what you copied.',
  hotp: 'This is a counter-based (HOTP) key. Ruvee supports time-based codes only.',
  migration:
    'This is a Google Authenticator export of several accounts. Add each account from its own site instead.',
  unsupported_scheme: 'This is not an authenticator link. It should start with otpauth://totp/.',
  malformed_uri: 'This otpauth:// link is not valid.',
  missing_secret: 'This link has no setup key (secret).',
  duplicate_parameter: 'This link names the same setting twice.',
  unsupported_algorithm: 'This link uses an algorithm Ruvee does not support.',
  unsupported_digits: 'Ruvee supports codes of 6, 7 or 8 digits.',
  unsupported_period: 'Ruvee supports codes that change every 10 to 300 seconds.',
  steam: 'Steam Guard codes are not supported.',
};

const QR_MESSAGES: Record<Exclude<QrResult, { ok: true }>['error'], string> = {
  not_image: 'That file is not an image Ruvee can read.',
  too_large: 'That image is larger than 20 MB.',
  no_code: 'No QR code was found in that image. Try a closer screenshot of the code.',
  failed: 'The image could not be read.',
};

/** 123 456, 123 4567, 1234 5678. */
export function formatCode(code: string): string {
  const half = Math.floor(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

/** The trade-off, stated where a code is added (W-A, §8.1 and §8.2). */
export function TotpTradeOff() {
  return (
    <Notice tone="caution">
      <p>
        With the authenticator in Ruvee, anyone who gets into your unlocked vault has both your
        password and your second factor for this site. For most sites that is a fair trade.
      </p>
      <p className="mt-1.5">
        Keep the authenticator for your email, your Ruvee server and your bank in a separate app or
        on a security key.
      </p>
    </Notice>
  );
}

/** The first code of what was pasted, so a wrong key is noticed while the site's setup is open. */
function Preview({ totp }: { totp: Totp }) {
  const [code, setCode] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      void totpCodes(totp, Date.now()).then((codes) => {
        if (cancelled) return;
        setCode(codes.code);
        timer = setTimeout(tick, Math.max(250, codes.validUntilMs - Date.now()));
      });
    };
    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [totp]);
  if (code === null) return null;
  return (
    <p className="text-small text-ink-secondary">
      Current code: <span className="font-mono text-body font-semibold">{formatCode(code)}</span>.
      Enter it on the site to finish setting up two-factor authentication.
    </p>
  );
}

/**
 * The editor's authenticator section. `value` is the draft's `totp`: undefined keeps what is
 * stored (the secret is never loaded into the page for an edit), null removes it, a string
 * replaces it.
 */
export function TotpEditorSection({
  hasStored,
  value,
  onChange,
  onHints,
  error,
}: {
  hasStored: boolean;
  value: string | null | undefined;
  onChange: (value: string | null | undefined) => void;
  onHints: (hints: { issuer?: string; account?: string }) => void;
  error?: string | undefined;
}) {
  const [qrMessage, setQrMessage] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const hinted = useRef<string | null>(null);
  const parsed = useMemo(
    () => (typeof value === 'string' && value.trim() ? parseTotpInput(value) : null),
    [value],
  );

  useEffect(() => {
    if (!parsed?.ok || typeof value !== 'string' || hinted.current === value) return;
    hinted.current = value;
    onHints({
      ...(parsed.issuer ? { issuer: parsed.issuer } : {}),
      ...(parsed.account ? { account: parsed.account } : {}),
    });
  }, [parsed, value, onHints]);

  const readImage = (file: File | undefined) => {
    if (!file) return;
    setQrMessage(null);
    setReading(true);
    void decodeQrImage(file).then((result) => {
      setReading(false);
      if (result.ok) onChange(result.text);
      else setQrMessage(QR_MESSAGES[result.error]);
    });
  };
  const imageFrom = (items: DataTransferItemList | undefined): File | undefined => {
    for (const item of items ?? [])
      if (item.kind === 'file' && item.type.startsWith('image/'))
        return item.getAsFile() ?? undefined;
    return undefined;
  };

  // An image pasted into the key field or onto the image button, or dropped on either.
  const onPaste = (event: ClipboardEvent) => {
    const image = imageFrom(event.clipboardData.items);
    if (image) {
      event.preventDefault();
      readImage(image);
    }
  };
  const onDragOver = (event: DragEvent) => {
    event.preventDefault();
  };
  const onDrop = (event: DragEvent) => {
    const image = imageFrom(event.dataTransfer.items);
    if (image) {
      event.preventDefault();
      readImage(image);
    }
  };

  if (value === undefined)
    return (
      <div className="flex flex-col gap-2">
        <div className="text-label font-semibold text-ink-secondary">Authenticator (2FA)</div>
        {hasStored ? (
          <div className="flex flex-wrap items-center gap-2">
            <span className="min-w-[200px] flex-1 text-body">
              Set up. Codes are shown on the item.
            </span>
            <Button
              size="sm"
              onClick={() => {
                onChange('');
              }}
            >
              Replace
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => {
                onChange(null);
              }}
            >
              Remove
            </Button>
          </div>
        ) : (
          <div>
            <Button
              size="sm"
              onClick={() => {
                onChange('');
              }}
            >
              Add authenticator
            </Button>
          </div>
        )}
      </div>
    );

  if (value === null)
    return (
      <div className="flex flex-col gap-2">
        <div className="text-label font-semibold text-ink-secondary">Authenticator (2FA)</div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="min-w-[200px] flex-1 text-body">
            The authenticator is removed when you save. Turn off two-factor authentication on the
            site first, or keep the codes somewhere else, or you may be locked out.
          </span>
          <Button
            size="sm"
            onClick={() => {
              onChange(undefined);
            }}
          >
            Undo
          </Button>
        </div>
      </div>
    );

  const inputError =
    error ?? (parsed && !parsed.ok ? TOTP_INPUT_MESSAGES[parsed.error] : undefined);
  return (
    <section
      aria-labelledby="totp-heading"
      className="flex flex-col gap-3 rounded-menu border border-line-soft p-4"
    >
      <div id="totp-heading" className="text-label font-semibold text-ink-secondary">
        {hasStored ? 'Replace authenticator' : 'Add authenticator'}
      </div>
      <TotpTradeOff />
      <div className="flex flex-col gap-1.5">
        <label htmlFor="totp-input" className="text-label font-semibold text-ink-secondary">
          Setup key or otpauth:// link
        </label>
        <input
          id="totp-input"
          type="text"
          value={value}
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          maxLength={TOTP_INPUT_MAX}
          aria-invalid={inputError ? true : undefined}
          aria-describedby={inputError ? 'totp-input-error' : 'totp-input-hint'}
          className={cx(
            'h-10 rounded-control border bg-surface px-3 font-mono text-body',
            inputError ? 'border-danger' : 'border-line-button',
          )}
          onChange={(event) => {
            onChange(event.target.value);
          }}
          onPaste={onPaste}
          onDragOver={onDragOver}
          onDrop={onDrop}
        />
        {inputError ? (
          <FieldError id="totp-input-error">{inputError}</FieldError>
        ) : (
          <p id="totp-input-hint" className="text-small text-ink-muted">
            On the site&apos;s two-factor setup page, choose the option to enter a key manually, or
            paste a screenshot of the QR code here.
          </p>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          aria-disabled={reading || undefined}
          onClick={() => {
            fileRef.current?.click();
          }}
          onPaste={onPaste}
          onDragOver={onDragOver}
          onDrop={onDrop}
        >
          {reading ? 'Reading image…' : 'Choose QR code image'}
        </Button>
        <span className="text-small text-ink-muted">or paste or drop a screenshot</span>
        <input
          ref={fileRef}
          type="file"
          accept="image/*"
          className="hidden"
          aria-label="QR code image"
          onChange={(event) => {
            readImage(event.target.files?.[0]);
            event.target.value = '';
          }}
        />
      </div>
      {qrMessage ? (
        <p className="text-small font-semibold text-danger-strong">{qrMessage}</p>
      ) : null}
      {parsed?.ok ? <Preview key={value} totp={parsed.totp} /> : null}
      <div>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            onChange(undefined);
          }}
        >
          {hasStored ? 'Keep the current authenticator' : 'Cancel'}
        </Button>
      </div>
    </section>
  );
}

/** The item detail's code: countdown, the next code near the end, copy, clock warning (§5). */
export function TotpRow({ client, itemId }: { client: VaultClient; itemId: string }) {
  const [view, setView] = useState<TotpView | null>(null);
  const [failed, setFailed] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, []);

  const expired = view === null || now >= view.validUntilMs;
  useEffect(() => {
    if (!expired) return;
    let cancelled = false;
    client.call('totp', { id: itemId }).then(
      (next) => {
        if (cancelled) return;
        setView(next);
        setFailed(false);
        setNow(Date.now());
      },
      (e: unknown) => {
        if (cancelled) return;
        setView(null);
        setFailed(!(e instanceof VaultClientError && e.code === 'locked'));
      },
    );
    return () => {
      cancelled = true;
    };
    // `now` advances the check each second; a new code is fetched only once this one expired.
  }, [client, itemId, expired, now]);

  if (!view)
    return failed ? (
      <div className="border-t border-line-soft py-3.5 text-body text-ink-muted">
        The authenticator code could not be computed.
      </div>
    ) : null;

  const remaining = Math.max(0, Math.ceil((view.validUntilMs - now) / 1000));
  const skew = view.clockSkewMs;
  return (
    <div className="flex flex-col gap-2 border-t border-line-soft py-3.5">
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-[220px] flex-1">
          <div className="mb-[3px] text-label font-semibold text-ink-muted">Authenticator code</div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-heading font-semibold tracking-[0.06em]">
              {formatCode(view.code)}
            </span>
            <span className="text-small text-ink-muted" aria-live="off">
              {remaining}s
            </span>
            {remaining <= 5 ? (
              <span className="text-small text-ink-muted">
                Next: <span className="font-mono">{formatCode(view.nextCode)}</span>
              </span>
            ) : null}
          </div>
          <div
            role="progressbar"
            aria-label="Time left for this code"
            aria-valuemin={0}
            aria-valuemax={view.period}
            aria-valuenow={remaining}
            className="mt-2 h-1 w-full max-w-[220px] overflow-hidden rounded-full bg-subtle"
          >
            <div
              className={cx(
                'h-full rounded-full',
                remaining <= 5 ? 'bg-caution-strong' : 'bg-brand',
              )}
              style={{ width: `${String((remaining / view.period) * 100)}%` }}
            />
          </div>
        </div>
        <div className="flex shrink-0 gap-1.5">
          <Button
            size="sm"
            icon={<CopyIcon size={15} />}
            aria-label="Copy authenticator code"
            onClick={() => {
              void client
                .call('totp', { id: itemId })
                .then((fresh) => copySecret(fresh.code))
                .then(() => {
                  setCopied(true);
                  setTimeout(() => {
                    setCopied(false);
                  }, 1500);
                });
            }}
          >
            <span aria-live="polite">{copied ? 'Copied' : 'Copy'}</span>
          </Button>
        </div>
      </div>
      {skew !== null && Math.abs(skew) > CLOCK_SKEW_WARNING_MS ? (
        <Notice tone="caution">
          This device&apos;s clock is about {String(Math.round(Math.abs(skew) / 1000))} seconds{' '}
          {skew > 0 ? 'ahead' : 'behind'}. Sites may reject these codes until the clock is
          corrected.
        </Notice>
      ) : null}
    </div>
  );
}
