export const ROUTES: Record<string, string> = {
  '/oauth/token': 'token', '/oauth/authorize': 'authorize', '/oauth/revoke': 'revoke',
  '/oauth/introspect': 'introspect', '/oauth/userinfo': 'userinfo', '/oauth/logout': 'logout',
  '/oauth/device_authorization': 'device', '/oauth/device': 'device', '/oauth/device/verify': 'device',
  '/oauth/par': 'par', '/connect/register': 'registration', '/connect/register/:client_id': 'registration',
  '/health': 'health', '/metrics': 'metrics',
  '/.well-known/jwks.json': 'discovery', '/.well-known/oauth-authorization-server': 'discovery',
  '/.well-known/openid-configuration': 'discovery',
};
const BUCKETS = [0.01, 0.05, 0.1, 0.5, 1, 5];
/** Process-local Prometheus exposition; only static route names and status classes are labels. */
export class Metrics {
  private readonly counts = new Map<string, number>();
  private readonly durations = new Map<string, number[]>();
  observe(_method: string, route: string, status: number, seconds: number): void {
    const operation = ROUTES[route] ?? 'other';
    const klass = status >= 100 && status <= 599 ? `${Math.floor(status / 100)}xx` : 'other';
    const label = `operation="${operation}",status="${klass}"`;
    this.counts.set(label, (this.counts.get(label) ?? 0) + 1);
    const buckets = this.durations.get(operation) ?? BUCKETS.map(() => 0);
    BUCKETS.forEach((bound, i) => { if (seconds <= bound) buckets[i] = (buckets[i] ?? 0) + 1; });
    this.durations.set(operation, buckets);
  }
  render(): string {
    const lines = ['# TYPE oauth_http_requests_total counter'];
    for (const [label, count] of this.counts) lines.push(`oauth_http_requests_total{${label}} ${count}`);
    lines.push('# TYPE oauth_http_request_duration_seconds histogram');
    for (const [operation, buckets] of this.durations) {
      BUCKETS.forEach((bound, i) => lines.push(`oauth_http_request_duration_seconds_bucket{operation="${operation}",le="${bound}"} ${buckets[i]}`));
      lines.push(`oauth_http_request_duration_seconds_bucket{operation="${operation}",le="+Inf"} ${this.total(operation)}`);
      lines.push(`oauth_http_request_duration_seconds_count{operation="${operation}"} ${this.total(operation)}`);
    }
    return `${lines.join('\n')}\n`;
  }
  private total(operation: string): number {
    let n = 0;
    for (const [label, count] of this.counts) if (label.startsWith(`operation="${operation}",`)) n += count;
    return n;
  }
}
