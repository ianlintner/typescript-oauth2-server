/**
 * Tracks the relying parties that received an ID token bearing a given `sid`.
 * Back-/front-channel logout (T-LOGOUT tickets 4/5) uses `clientsFor` to decide
 * whom to notify; `end` discards the record when the OP session terminates.
 * The port has no persistent session store: hosts may supply their own
 * implementation; conformance mode uses {@link InMemorySessionParticipation}.
 */
export interface SessionParticipation {
  record(sid: string, clientId: string): void | Promise<void>;
  clientsFor(sid: string): string[] | Promise<string[]>;
  end(sid: string): void | Promise<void>;
}

/** Session facts handed to the single logout-notification hook (tickets 4/5). */
export interface LogoutContext {
  /** OP session identifier from the ending session or the `id_token_hint`'s `sid`; null when unknown. */
  sid: string | null;
  /** End-user subject from the hint. */
  sub: string;
  /** Relying parties that received an ID token carrying `sid` (D2). */
  clients: string[];
}

export class InMemorySessionParticipation implements SessionParticipation {
  readonly #clientsBySid = new Map<string, Set<string>>();

  record(sid: string, clientId: string): void {
    let clients = this.#clientsBySid.get(sid);
    if (!clients) {
      clients = new Set<string>();
      this.#clientsBySid.set(sid, clients);
    }
    clients.add(clientId);
  }

  clientsFor(sid: string): string[] {
    return [...(this.#clientsBySid.get(sid) ?? [])];
  }

  end(sid: string): void {
    this.#clientsBySid.delete(sid);
  }
}
