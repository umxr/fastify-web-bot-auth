import { describe, expect, it } from 'vitest';
import { parseSignatureAgent } from '../src/signature-agent.js';

describe('parseSignatureAgent', () => {
  it('parses the RFC 8941 sf-string (quoted) form', () => {
    expect(parseSignatureAgent('"https://example.com"')).toBe('https://example.com');
  });

  it('parses the legacy bare-string form', () => {
    expect(parseSignatureAgent('https://example.com')).toBe('https://example.com');
  });

  it('normalizes to the origin', () => {
    expect(parseSignatureAgent('"https://example.com/some/path?x=1"')).toBe('https://example.com');
    expect(parseSignatureAgent('https://example.com:443/x')).toBe('https://example.com');
    expect(parseSignatureAgent('https://example.com:8443')).toBe('https://example.com:8443');
  });

  it('takes the first value when the header was sent multiple times', () => {
    expect(parseSignatureAgent(['"https://a.example"', '"https://b.example"'])).toBe(
      'https://a.example',
    );
  });

  it('trims surrounding whitespace', () => {
    expect(parseSignatureAgent('  "https://example.com"  ')).toBe('https://example.com');
  });

  it('rejects non-https origins', () => {
    expect(parseSignatureAgent('"http://example.com"')).toBeNull();
    expect(parseSignatureAgent('http://example.com')).toBeNull();
    expect(parseSignatureAgent('ftp://example.com')).toBeNull();
  });

  it('rejects URLs with credentials', () => {
    expect(parseSignatureAgent('https://user:pass@example.com')).toBeNull();
  });

  it('rejects values that are not URLs', () => {
    expect(parseSignatureAgent('not a url')).toBeNull();
    expect(parseSignatureAgent('"not a url"')).toBeNull();
    expect(parseSignatureAgent('example.com')).toBeNull();
  });

  it('rejects empty and missing values', () => {
    expect(parseSignatureAgent(undefined)).toBeNull();
    expect(parseSignatureAgent('')).toBeNull();
    expect(parseSignatureAgent('   ')).toBeNull();
    expect(parseSignatureAgent([])).toBeNull();
  });

  it('rejects localhost and private/loopback/link-local IP literals (SSRF guard)', () => {
    expect(parseSignatureAgent('https://localhost')).toBeNull();
    expect(parseSignatureAgent('https://sub.localhost')).toBeNull();
    expect(parseSignatureAgent('"https://LOCALHOST:8443"')).toBeNull();
    expect(parseSignatureAgent('https://127.0.0.1')).toBeNull();
    expect(parseSignatureAgent('https://127.255.255.254')).toBeNull();
    expect(parseSignatureAgent('https://10.0.0.5')).toBeNull();
    expect(parseSignatureAgent('https://172.16.0.1')).toBeNull();
    expect(parseSignatureAgent('https://172.31.255.255')).toBeNull();
    expect(parseSignatureAgent('https://192.168.1.1')).toBeNull();
    expect(parseSignatureAgent('https://169.254.169.254')).toBeNull();
    expect(parseSignatureAgent('https://0.0.0.0')).toBeNull();
    expect(parseSignatureAgent('https://[::1]')).toBeNull();
    expect(parseSignatureAgent('https://[::]')).toBeNull();
    expect(parseSignatureAgent('https://[fe80::1]')).toBeNull();
    expect(parseSignatureAgent('https://[fd00::1]')).toBeNull();
    expect(parseSignatureAgent('https://[fc00::1]')).toBeNull();
    expect(parseSignatureAgent('https://[::ffff:127.0.0.1]')).toBeNull();
  });

  it('allows public hosts, public IP literals, and boundary private-range neighbors', () => {
    expect(parseSignatureAgent('https://example.com')).toBe('https://example.com');
    expect(parseSignatureAgent('https://8.8.8.8')).toBe('https://8.8.8.8');
    expect(parseSignatureAgent('https://172.15.0.1')).toBe('https://172.15.0.1');
    expect(parseSignatureAgent('https://172.32.0.1')).toBe('https://172.32.0.1');
    expect(parseSignatureAgent('https://192.169.0.1')).toBe('https://192.169.0.1');
    expect(parseSignatureAgent('https://[2606:4700::1111]')).toBe('https://[2606:4700::1111]');
    expect(parseSignatureAgent('https://localhost.example.com')).toBe(
      'https://localhost.example.com',
    );
  });

  it('rejects structured values that are not strings or tokens', () => {
    expect(parseSignatureAgent('?1')).toBeNull(); // boolean
    expect(parseSignatureAgent('42')).toBeNull(); // integer
    expect(parseSignatureAgent('(a b)')).toBeNull(); // inner list is not an item
  });
});
