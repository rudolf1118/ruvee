/**
 * The vault engine shared by the web app and the extension: key handling, items, sync, pairing,
 * recovery and rotations, over an injected API transport, store and OPAQUE client. Each client
 * runs it in its own isolated context (a web worker, the extension service worker).
 */
export * from './api.js';
export * from './dispatch.js';
export * from './export-file.js';
export * from './item-schema.js';
export * from './password-policy.js';
export * from './protocol.js';
export * from './store.js';
export * from './vault-engine.js';
