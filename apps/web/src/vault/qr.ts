/** Images larger than this are refused before decoding. */
export const QR_IMAGE_MAX_BYTES = 20 * 1024 * 1024;
const QR_TIMEOUT_MS = 15_000;

export type QrResult =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly error: 'not_image' | 'too_large' | 'no_code' | 'failed' };

/**
 * Reads the QR code in an image the user pasted, dropped or picked (totp-authenticator.md §3.3).
 * A fresh worker decodes it and is terminated afterwards; the image is never uploaded or kept.
 */
export async function decodeQrImage(file: Blob): Promise<QrResult> {
  if (!file.type.startsWith('image/')) return { ok: false, error: 'not_image' };
  if (file.size > QR_IMAGE_MAX_BYTES) return { ok: false, error: 'too_large' };
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return { ok: false, error: 'not_image' };
  }
  const worker = new Worker(new URL('./qr.worker.ts', import.meta.url), {
    type: 'module',
    name: 'ruvee-qr',
  });
  try {
    const text = await new Promise<string | null>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('timeout'));
      }, QR_TIMEOUT_MS);
      worker.onmessage = (event: MessageEvent<{ text: string | null }>) => {
        clearTimeout(timer);
        resolve(typeof event.data.text === 'string' ? event.data.text : null);
      };
      worker.onerror = () => {
        clearTimeout(timer);
        reject(new Error('worker'));
      };
      worker.postMessage(bitmap, [bitmap]);
    });
    return text === null ? { ok: false, error: 'no_code' } : { ok: true, text };
  } catch {
    return { ok: false, error: 'failed' };
  } finally {
    worker.terminate();
  }
}
