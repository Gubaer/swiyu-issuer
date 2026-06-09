import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { Credential } from './credentials-service';
import { CredentialsStore } from './credentials-store';

function credential(id: string, overrides: Partial<Credential> = {}): Credential {
  return {
    id,
    issuer_id: 'iss1',
    credential_offer_id: `offer-${id}`,
    vct: 'urn:demo',
    holder_key_jkt: 'jkt',
    status_list_id: 'sl1',
    status_list_index: 0,
    state: 'active',
    expired: false,
    issued_at: '2026-01-01T00:00:00Z',
    expires_at: '2027-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('CredentialsStore', () => {
  let store: CredentialsStore;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    store = TestBed.inject(CredentialsStore);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('loads the first page for an issuer, replacing prior state', () => {
    store.loadFor('iss1');
    expect(store.loading()).toBe(true);

    httpMock
      .expectOne('/api/issuers/iss1/credentials')
      .flush({ items: [credential('c1')], next_cursor: 'cursor-1' });

    expect(store.loading()).toBe(false);
    expect(store.items().map((c) => c.id)).toEqual(['c1']);
    expect(store.hasMore()).toBe(true);

    // A second load resets the accumulated rows rather than appending.
    store.loadFor('iss1');
    httpMock
      .expectOne('/api/issuers/iss1/credentials')
      .flush({ items: [credential('c2')], next_cursor: null });

    expect(store.items().map((c) => c.id)).toEqual(['c2']);
    expect(store.hasMore()).toBe(false);
  });

  it('appends the next page on loadMore using the stored cursor', () => {
    store.loadFor('iss1');
    httpMock
      .expectOne('/api/issuers/iss1/credentials')
      .flush({ items: [credential('c1')], next_cursor: 'cursor-1' });

    store.loadMore();
    httpMock
      .expectOne(
        (req) =>
          req.url === '/api/issuers/iss1/credentials' && req.params.get('cursor') === 'cursor-1',
      )
      .flush({ items: [credential('c2')], next_cursor: null });

    expect(store.items().map((c) => c.id)).toEqual(['c1', 'c2']);
    expect(store.hasMore()).toBe(false);
  });

  it('drops a stale response when the issuer changed mid-flight', () => {
    store.loadFor('iss1');
    const stale = httpMock.expectOne('/api/issuers/iss1/credentials');

    store.loadFor('iss2');
    const fresh = httpMock.expectOne('/api/issuers/iss2/credentials');

    // The first request resolves after the switch; its result must be ignored.
    stale.flush({ items: [credential('old')], next_cursor: null });
    expect(store.items()).toEqual([]);

    fresh.flush({ items: [credential('new')], next_cursor: null });
    expect(store.items().map((c) => c.id)).toEqual(['new']);
  });

  it('sets an error message when the list request fails', () => {
    store.loadFor('iss1');
    httpMock.expectOne('/api/issuers/iss1/credentials').error(new ProgressEvent('network'));

    expect(store.error()).toBeTruthy();
    expect(store.loading()).toBe(false);
  });

  it('applyUpdate replaces only the matching row with the server record', () => {
    store.loadFor('iss1');
    httpMock
      .expectOne('/api/issuers/iss1/credentials')
      .flush({ items: [credential('c1'), credential('c2')], next_cursor: null });

    store.applyUpdate(credential('c2', { state: 'revoked', expired: true }));

    const [first, second] = store.items();
    // The untouched row is unchanged; only the matching row reflects the update.
    expect(first.id).toBe('c1');
    expect(first.state).toBe('active');
    expect(second.id).toBe('c2');
    expect(second.state).toBe('revoked');
    expect(second.expired).toBe(true);
  });
});
