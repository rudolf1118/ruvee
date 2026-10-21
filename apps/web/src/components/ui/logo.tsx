export function LogoMark({
  size = 28,
  tone = 'solid',
}: {
  size?: number;
  tone?: 'solid' | 'soft';
}) {
  const soft = tone === 'soft';
  const fill = soft ? 'var(--color-brand-soft)' : 'var(--color-brand)';
  const stroke = soft ? 'var(--color-brand)' : '#fff';
  const width = soft ? 2.4 : 2.6;
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="9" fill={fill} />
      <circle cx="16" cy="13.5" r="5" fill="none" stroke={stroke} strokeWidth={width} />
      <path d="M16 18.5v6" stroke={stroke} strokeWidth={width} strokeLinecap="round" />
    </svg>
  );
}

export function Logo({ size = 28 }: { size?: number }) {
  return (
    <div className="flex items-center gap-2.5">
      <LogoMark size={size} />
      <span className="text-[19px] font-bold tracking-wordmark">ruvee</span>
    </div>
  );
}
