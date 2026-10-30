const MiB = 1024 * 1024;

// Profile 1 as proposed, plus comparison points. Nothing here is a recommendation.
export const profiles = [
  { label: 'OWASP minimum 19MiB t=2', t: 2, mem: 19 * MiB },
  { label: 'profile-1 64MiB t=3', t: 3, mem: 64 * MiB },
  { label: '128MiB t=3', t: 3, mem: 128 * MiB },
  { label: 'profile-2 256MiB t=3', t: 3, mem: 256 * MiB },
];
