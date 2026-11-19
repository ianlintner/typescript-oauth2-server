import { BlockList, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

/** A resolved address, as returned by `dns.promises.lookup(host, { all: true })`. */
export interface ResolvedAddress {
  address: string;
  family: number;
}
export type HostResolver = (host: string) => Promise<ResolvedAddress[]>;

/** Ranges that are not routable public unicast space. */
const NON_PUBLIC = new BlockList();
const V4: ReadonlyArray<[string, number]> = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
];
for (const [net, prefix] of V4) NON_PUBLIC.addSubnet(net, prefix, 'ipv4');
const V6: ReadonlyArray<[string, number]> = [
  ['::', 128], ['::1', 128], ['100::', 64], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
];
for (const [net, prefix] of V6) NON_PUBLIC.addSubnet(net, prefix, 'ipv6');

/** Strip the brackets `URL#hostname` keeps around an IPv6 literal. */
function bare(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/** Extract the IPv4 address embedded in an IPv4-mapped (::ffff:0:0/96) or NAT64 (64:ff9b::/96) IPv6 address. */
function embeddedV4(ip: string): string | undefined {
  const m = /^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (m) return m[1];
  const h = /^(?:::ffff:|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (h) {
    const hi = parseInt(h[1]!, 16);
    const lo = parseInt(h[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return undefined;
}

/** True only for a syntactically valid IP literal in public unicast space. Anything unparsable is non-public. */
export function isPublicAddress(ip: string): boolean {
  const addr = bare(ip);
  const family = isIP(addr);
  if (family === 4) return !NON_PUBLIC.check(addr, 'ipv4');
  if (family === 6) {
    const v4 = embeddedV4(addr);
    if (v4 !== undefined) return isPublicAddress(v4);
    return !NON_PUBLIC.check(addr, 'ipv6');
  }
  return false;
}

/** True when the host is an IP literal (after URL normalisation of numeric forms). */
export function isIpLiteral(host: string): boolean {
  return isIP(bare(host)) !== 0;
}

const defaultResolver: HostResolver = (host) => lookup(host, { all: true });

/** Resolve a URL host to the addresses a connection could use; an IP literal resolves to itself. */
export async function parseHostToIps(host: string, resolver: HostResolver = defaultResolver): Promise<string[]> {
  const h = bare(host);
  if (isIP(h) !== 0) return [h];
  return (await resolver(h)).map((r) => r.address);
}

export interface NetGuardOptions {
  /** Test-only: replace DNS resolution. */
  resolver?: HostResolver;
  /** Test-only: permit non-public addresses at fetch time. Never reachable from configuration. */
  allowPrivate?: boolean;
}

let guard: NetGuardOptions = {};

/** Test seam: override the resolver and/or allow private addresses. Call with no argument to reset. */
export function setNetGuard(opts: NetGuardOptions = {}): void {
  guard = opts;
}

/**
 * Throw unless every address the host resolves to is public. The error is deliberately
 * generic: it must not reveal which range was hit.
 */
export async function assertPublicHost(host: string): Promise<void> {
  if (guard.allowPrivate === true) return;
  const ips = await parseHostToIps(host, guard.resolver ?? defaultResolver);
  if (ips.length === 0 || !ips.every(isPublicAddress)) throw new Error('JWKS endpoint not permitted');
}
