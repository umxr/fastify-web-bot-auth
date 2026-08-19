import { Token, parseItem } from 'structured-headers';

/**
 * Parse a `Signature-Agent` header value into a validated https origin.
 *
 * Accepts both wire forms seen in the wild:
 * - RFC 8941 sf-string (quoted): `Signature-Agent: "https://example.com"`
 * - Legacy bare string: `Signature-Agent: https://example.com`
 *
 * Returns the normalized https origin (e.g. `https://example.com`) or `null`
 * when the value is not a valid https origin.
 */
export function parseSignatureAgent(value: string | string[] | undefined): string | null {
  if (value === undefined) return null;
  const raw = (Array.isArray(value) ? value[0] : value)?.trim();
  if (!raw) return null;

  let candidate: string | null = null;
  try {
    const [item] = parseItem(raw);
    if (typeof item === 'string') {
      // sf-string form: "https://example.com"
      candidate = item;
    } else if (item instanceof Token) {
      // A bare URL happens to be a valid RFC 8941 token.
      candidate = item.toString();
    }
  } catch {
    // Not a valid structured field item; fall back to the bare string.
  }
  if (candidate === null) candidate = raw;

  return toHttpsOrigin(candidate);
}

function toHttpsOrigin(candidate: string): string | null {
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:') return null;
  if (url.username !== '' || url.password !== '') return null;
  if (isForbiddenHost(url.hostname)) return null;
  return url.origin;
}

/**
 * SSRF guard: hosts that must never be fetched as key directories —
 * `localhost` names and IP literals in loopback, private, link-local, or
 * unspecified ranges. Public IP literals and non-443 ports stay allowed.
 * Note: this checks literals only; DNS-rebinding-grade SSRF needs
 * network-level egress controls (see README threat model).
 */
export function isForbiddenHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (isForbiddenIpv4(host)) return true;
  if (host.includes(':')) return isForbiddenIpv6(host);
  return false;
}

function isForbiddenIpv4(host: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return false;
  const octets = match.slice(1).map(Number);
  if (octets.some((o) => o > 255)) return false; // not a real IPv4 literal
  const [a, b] = octets as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8 unspecified
  if (a === 127) return true; // loopback
  if (a === 10) return true; // private
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

function isForbiddenIpv6(host: string): boolean {
  if (host === '::' || host === '::1') return true; // unspecified / loopback
  const firstGroup = host.split(':', 1)[0] ?? '';
  if (/^f[cd][0-9a-f]{0,2}$/.test(firstGroup)) return true; // fc00::/7 unique local
  if (/^fe[89ab][0-9a-f]?$/.test(firstGroup)) return true; // fe80::/10 link-local
  // IPv4-mapped forms: dotted (::ffff:127.0.0.1) or canonical hex (::ffff:7f00:1).
  const embedded = /(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(host);
  if (embedded?.[1]) return isForbiddenIpv4(embedded[1]);
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (mappedHex?.[1] && mappedHex[2]) {
    const hi = Number.parseInt(mappedHex[1], 16);
    const lo = Number.parseInt(mappedHex[2], 16);
    return isForbiddenIpv4(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
  }
  return false;
}
