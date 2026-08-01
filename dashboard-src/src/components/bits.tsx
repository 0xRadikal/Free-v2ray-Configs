import { useEffect, useState, type ReactNode } from 'react';
import { Check, Copy, ExternalLink } from 'lucide-react';
import { safeHref } from '@/lib/guards';

/* Small shared pieces. Kept presentational: nothing here decides what a number
 * means, only how it is shown. */

export function Eyebrow({ children }: { children: ReactNode }) {
  return <div className="eyebrow">{children}</div>;
}

/** A page section with a stable id (used by the rail's anchor nav). */
export function Section({
  id,
  title,
  lede,
  children,
}: {
  id: string;
  title: string;
  lede?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-6">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b pb-2">
        <h2 className="text-[17px] font-semibold tracking-tight">{title}</h2>
        {lede ? <p className="text-[13px] text-muted-foreground">{lede}</p> : null}
      </div>
      {children}
    </section>
  );
}

/** One measured figure. `sub` is where the derivation goes, never a decoration. */
export function Kpi({
  label,
  value,
  sub,
  tone = 'default',
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: 'default' | 'ok' | 'warn' | 'bad';
}) {
  const toneCls =
    tone === 'ok'
      ? 'text-[hsl(var(--sig-ok))]'
      : tone === 'warn'
        ? 'text-[hsl(var(--sig-warn))]'
        : tone === 'bad'
          ? 'text-[hsl(var(--sig-bad))]'
          : '';
  return (
    <div className="panel px-3.5 py-3">
      <div className="eyebrow">{label}</div>
      <div className={`fig mt-1.5 text-2xl font-semibold leading-none ${toneCls}`}>{value}</div>
      {sub ? <div className="mt-1.5 text-[12px] leading-snug text-muted-foreground">{sub}</div> : null}
    </div>
  );
}

export function Pill({ kind, children }: { kind: string; children: ReactNode }) {
  const known = ['ok', 'empty', 'fail'].includes(kind) ? kind : 'unknown';
  return <span className={`pill pill-${known}`}>{children}</span>;
}

/** Proportional bar. `frac` is expected in 0..1 and is clamped, because it is
 *  derived from published numbers and a bar wider than its track is a lie. */
export function Meter({ frac, zero = false }: { frac: number; zero?: boolean }) {
  const w = Math.max(0, Math.min(1, isFinite(frac) ? frac : 0)) * 100;
  return (
    <div className={`meter${zero ? ' is-zero' : ''}`} aria-hidden="true">
      <i style={{ width: `${w}%` }} />
    </div>
  );
}

/**
 * Copy-to-clipboard. Falls back to a hidden textarea + execCommand, because
 * navigator.clipboard is unavailable on insecure origins and on some of the
 * older browsers this audience actually uses — and a button that silently does
 * nothing is worse than no button.
 */
export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1600);
    return () => clearTimeout(t);
  }, [done]);

  async function doCopy() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        setDone(true);
        return;
      }
    } catch {
      /* fall through to the legacy path */
    }
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      setDone(true);
    } catch {
      /* leave the button un-ticked rather than claim a copy that did not happen */
    }
  }

  return (
    <button
      type="button"
      onClick={doCopy}
      title={label}
      aria-label={done ? 'Copied' : label}
      className="inline-flex items-center gap-1 border px-1.5 py-0.5 text-[11px] text-muted-foreground
                 transition-colors hover:bg-secondary hover:text-foreground"
      style={{ borderRadius: 'var(--radius)' }}
    >
      {done ? <Check size={12} className="text-[hsl(var(--sig-ok))]" /> : <Copy size={12} />}
      <span className="fig">{done ? 'copied' : 'copy'}</span>
    </button>
  );
}

/**
 * A link that is only a link when the URL survives safeHref. A rejected URL
 * degrades to plain text — never to href="#", which is not inert: it navigates
 * to the top of the page, so a reader who clicks what looks like a download
 * link gets a silent scroll instead.
 */
export function SafeLink({
  url,
  children,
  className = '',
  showIcon = false,
}: {
  url: unknown;
  children?: ReactNode;
  className?: string;
  showIcon?: boolean;
}) {
  const href = safeHref(url);
  const body = children ?? String(url ?? '');
  if (!href) return <span className={className}>{body}</span>;
  return (
    <a
      href={href}
      rel="noopener noreferrer"
      target="_blank"
      className={`text-primary underline-offset-2 hover:underline ${className}`}
    >
      {body}
      {showIcon ? <ExternalLink size={11} className="ml-1 inline-block align-baseline" /> : null}
    </a>
  );
}

/** Renders a {label,count} distribution as a compact ranked bar list. */
export function Distribution({
  entries,
  emptyText = 'nothing recorded',
}: {
  entries: Array<[string, number]>;
  emptyText?: string;
}) {
  if (!entries.length) {
    return <p className="text-[13px] text-muted-foreground">{emptyText}</p>;
  }
  const max = entries.reduce((m, [, v]) => Math.max(m, v), 0);
  return (
    <ul className="space-y-1.5">
      {entries.map(([k, v]) => (
        <li key={k} className="grid grid-cols-[minmax(6.5rem,auto)_1fr_auto] items-center gap-2.5">
          <span className="fig truncate text-[12px] text-muted-foreground" title={k}>
            {k}
          </span>
          <Meter frac={max > 0 ? v / max : 0} zero={v === 0} />
          <span className="fig w-14 text-right text-[12px]">{v.toLocaleString('en-US')}</span>
        </li>
      ))}
    </ul>
  );
}
