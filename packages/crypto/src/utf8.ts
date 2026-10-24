import { RuveeCryptoError } from './errors.js';

// The build has neither DOM nor Node types; both runtimes provide these WHATWG globals.
interface Utf8Encoder {
  encode(input: string): Uint8Array;
}
interface Utf8Decoder {
  decode(input: Uint8Array): string;
}
interface Utf8Globals {
  TextEncoder?: new () => Utf8Encoder;
  TextDecoder?: new (label: string, options: { fatal: boolean; ignoreBOM: boolean }) => Utf8Decoder;
}

let encoder: Utf8Encoder | undefined;
let decoder: Utf8Decoder | undefined;

function codecs(): { encoder: Utf8Encoder; decoder: Utf8Decoder } {
  if (!encoder || !decoder) {
    const g = globalThis as Utf8Globals;
    if (!g.TextEncoder || !g.TextDecoder)
      throw new RuveeCryptoError('library_failure', { reason: 'initialization_failed' });
    encoder = new g.TextEncoder();
    // ignoreBOM keeps a leading U+FEFF as content instead of silently dropping it.
    decoder = new g.TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  }
  return { encoder, decoder };
}

/** UTF-8 of a string the caller has already checked to be well formed. */
export function utf8Encode(text: string): Uint8Array {
  return codecs().encoder.encode(text);
}

/** Strict UTF-8 decoding; returns undefined for any invalid sequence. */
export function utf8DecodeStrict(bytes: Uint8Array): string | undefined {
  try {
    return codecs().decoder.decode(bytes);
  } catch {
    return undefined;
  }
}
