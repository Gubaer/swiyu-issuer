import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { Me, SessionService } from './session-service';

const ME: Me = {
  identity: { iss: 'http://localhost:8083/realms/swiyu-issuer', sub: 'u1' },
  selected_account: {
    id: 'a1',
    tenant_id: 't1',
    tenant_display_name: 'SWIYU Dev',
    display_name: 'Dev User',
  },
  accounts: [
    { id: 'a1', tenant_id: 't1', tenant_display_name: 'SWIYU Dev', display_name: 'Dev User' },
  ],
};

describe('SessionService', () => {
  let service: SessionService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SessionService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('loads /api/me and exposes the session', async () => {
    const loaded = service.load();
    httpMock.expectOne('/api/me').flush(ME);
    await loaded;

    expect(service.isAuthenticated()).toBe(true);
    expect(service.me()).toEqual(ME);
  });

  it('treats a 401 as unauthenticated rather than erroring', async () => {
    const loaded = service.load();
    httpMock.expectOne('/api/me').flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });
    await loaded;

    expect(service.isAuthenticated()).toBe(false);
    expect(service.me()).toBeNull();
  });

  it('fetches once and caches: a second load makes no request', async () => {
    const loaded = service.load();
    httpMock.expectOne('/api/me').flush(ME);
    await loaded;

    await service.load();
    httpMock.expectNone('/api/me');
    expect(service.me()).toEqual(ME);
  });

  it('shares one in-flight request across concurrent callers', async () => {
    const first = service.load();
    const second = service.load();
    // Exactly one request despite two concurrent callers.
    httpMock.expectOne('/api/me').flush(ME);
    await Promise.all([first, second]);

    expect(service.me()).toEqual(ME);
  });

  it('reload() forces a fresh fetch', async () => {
    const loaded = service.load();
    httpMock.expectOne('/api/me').flush(ME);
    await loaded;

    const reloaded = service.reload();
    httpMock.expectOne('/api/me').flush(ME);
    await reloaded;

    expect(service.me()).toEqual(ME);
  });

  it('clear() drops the cached session and allows a re-fetch', async () => {
    const loaded = service.load();
    httpMock.expectOne('/api/me').flush(ME);
    await loaded;

    service.clear();
    expect(service.me()).toBeNull();
    expect(service.isAuthenticated()).toBe(false);

    const reloaded = service.load();
    httpMock.expectOne('/api/me').flush(ME);
    await reloaded;
    expect(service.me()).toEqual(ME);
  });
});
