import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

/** The logged-in federated identity. */
export interface Identity {
  iss: string;
  sub: string;
}

/** A user account the identity is linked to. */
export interface Account {
  id: string;
  tenant_id: string;
  /** Human-readable tenant name; `null` when the tenant has none set. */
  tenant_display_name: string | null;
  /** Precomputed label (IDP name → provisioning name → id). */
  display_name: string;
}

/** The `/api/me` payload. */
export interface Me {
  identity: Identity;
  selected_account: Account;
  accounts: Account[];
}

/**
 * Holds the current session. `load()` fetches `/api/me` once and caches it; a
 * `401` (not logged in) leaves the session unauthenticated rather than erroring.
 */
@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly http = inject(HttpClient);

  private readonly _me = signal<Me | null>(null);
  /** The current session, or `null` when unauthenticated. */
  readonly me = this._me.asReadonly();
  readonly isAuthenticated = computed(() => this._me() !== null);

  private loaded = false;
  private inflight: Promise<void> | null = null;

  /**
   * Ensures `/api/me` has been fetched (once). Concurrent callers share the same
   * in-flight request. A `401`/error resolves to the unauthenticated state.
   */
  load(): Promise<void> {
    if (this.loaded) {
      return Promise.resolve();
    }
    // Share one in-flight request across concurrent callers.
    this.inflight ??= this.fetchMe();
    return this.inflight;
  }

  private async fetchMe(): Promise<void> {
    try {
      this._me.set(await firstValueFrom(this.http.get<Me>('/api/me')));
    } catch {
      this._me.set(null);
    } finally {
      this.loaded = true;
      this.inflight = null;
    }
  }

  /** Forces a re-fetch, e.g. after switching the selected account. */
  reload(): Promise<void> {
    this.loaded = false;
    this.inflight = null;
    return this.load();
  }

  /** Drops the cached session (e.g. on a mid-session `401`). */
  clear(): void {
    this._me.set(null);
    this.loaded = false;
    this.inflight = null;
  }
}
