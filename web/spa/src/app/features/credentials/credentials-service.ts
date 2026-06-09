import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export type CredentialState = 'active' | 'suspended' | 'revoked';

// List and detail return the same shape — credentials carry no claims, so there
// is no summary/full split as there is for credential offers.
export interface Credential {
  id: string;
  issuer_id: string;
  credential_offer_id: string;
  vct: string;
  holder_key_jkt: string;
  status_list_id: string;
  status_list_index: number;
  state: CredentialState;
  expired: boolean;
  issued_at: string;
  expires_at: string;
}

export interface CredentialsResponse {
  items: Credential[];
  next_cursor: string | null;
}

export interface ListOptions {
  limit?: number;
  cursor?: string | null;
  state?: CredentialState;
  vct?: string;
}

@Injectable({ providedIn: 'root' })
export class CredentialsService {
  private readonly http = inject(HttpClient);

  list(issuerId: string, options?: ListOptions): Observable<CredentialsResponse> {
    let params = new HttpParams();
    if (options?.limit !== undefined) {
      params = params.set('limit', String(options.limit));
    }
    if (options?.cursor) {
      params = params.set('cursor', options.cursor);
    }
    if (options?.state) {
      params = params.set('state', options.state);
    }
    if (options?.vct) {
      params = params.set('vct', options.vct);
    }
    return this.http.get<CredentialsResponse>(`/api/issuers/${issuerId}/credentials`, {
      params,
    });
  }

  get(issuerId: string, credentialId: string): Observable<Credential> {
    return this.http.get<Credential>(`/api/issuers/${issuerId}/credentials/${credentialId}`);
  }

  // The three lifecycle actions are synchronous: each returns the full updated
  // record. The UI label is *Resume*, but the API verb is *unsuspend*.
  suspend(issuerId: string, credentialId: string): Observable<Credential> {
    return this.http.post<Credential>(
      `/api/issuers/${issuerId}/credentials/${credentialId}/suspend`,
      {},
    );
  }

  resume(issuerId: string, credentialId: string): Observable<Credential> {
    return this.http.post<Credential>(
      `/api/issuers/${issuerId}/credentials/${credentialId}/unsuspend`,
      {},
    );
  }

  revoke(issuerId: string, credentialId: string): Observable<Credential> {
    return this.http.post<Credential>(
      `/api/issuers/${issuerId}/credentials/${credentialId}/revoke`,
      {},
    );
  }
}
