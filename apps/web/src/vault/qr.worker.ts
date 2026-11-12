import jsQR from 'jsqr';

/**
 * Decodes one QR code from one image, then is terminated by its caller (totp-authenticator.md
 * §3.3). It runs apart from the vault worker and the page: the image is untrusted input and the
 * decoder is third-party code, so neither shares a realm with keys. It holds no vault data and
 * returns only the decoded text.
 */

/** Larger images are scaled down before decoding; a QR code stays readable well below this. */
const MAX_SIDE = 3000;

self.onmessage = (event: MessageEvent<ImageBitmap>) => {
  const bitmap = event.data;
  let text: string | null = null;
  try {
    const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = new OffscreenCanvas(width, height);
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (context) {
      context.drawImage(bitmap, 0, 0, width, height);
      const image = context.getImageData(0, 0, width, height);
      text = jsQR(image.data, width, height, { inversionAttempts: 'attemptBoth' })?.data ?? null;
      image.data.fill(0);
      context.clearRect(0, 0, width, height);
    }
  } catch {
    text = null;
  } finally {
    bitmap.close();
  }
  self.postMessage({ text });
};
