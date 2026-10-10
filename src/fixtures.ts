export interface Scenario {
  id: string;
  rfc: string;
  request: { method: 'GET' | 'POST'; path: string };
  expect: { status: number };
}

export function parseScenario(input: unknown): Scenario {
  if (typeof input !== 'object' || input === null) {
    throw new TypeError('scenario must be an object');
  }
  const value = input as Record<string, unknown>;
  if (typeof value.id !== 'string' || value.id.trim() === '') {
    throw new TypeError('scenario id must be nonempty');
  }
  if (typeof value.rfc !== 'string' || value.rfc.trim() === '') {
    throw new TypeError('RFC reference must be nonempty');
  }
  if (typeof value.request !== 'object' || value.request === null || Array.isArray(value.request)) {
    throw new TypeError('request must be an object');
  }
  const request = value.request as Record<string, unknown>;
  if (typeof value.expect !== 'object' || value.expect === null || Array.isArray(value.expect)) {
    throw new TypeError('expectation must be an object');
  }
  const expected = value.expect as Record<string, unknown>;
  if (request.method !== 'GET' && request.method !== 'POST') {
    throw new TypeError('request method must be GET or POST');
  }
  if (typeof request.path !== 'string' || !request.path.startsWith('/')) {
    throw new TypeError('request path must start with /');
  }
  if (!Number.isInteger(expected.status) || (expected.status as number) < 100 || (expected.status as number) > 599) {
    throw new TypeError('expected status must be an HTTP status code');
  }
  return {
    id: value.id as string,
    rfc: value.rfc as string,
    request: { method: request.method as Scenario['request']['method'], path: request.path as string },
    expect: { status: expected.status as number },
  };
}
