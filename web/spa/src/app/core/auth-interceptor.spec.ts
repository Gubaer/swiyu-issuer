import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';

import { authInterceptor } from './auth-interceptor';
import { SessionService } from './session-service';

describe('authInterceptor', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let router: Router;
  let session: { clear: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    session = { clear: vi.fn() };
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: SessionService, useValue: session },
      ],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
  });

  afterEach(() => httpMock.verify());

  it('adds the X-Requested-With header to /api/* requests', () => {
    http.get('/api/issuers').subscribe();
    const req = httpMock.expectOne('/api/issuers');
    expect(req.request.headers.get('X-Requested-With')).toBe('XMLHttpRequest');
    req.flush([]);
  });

  it('leaves non-/api requests untouched', () => {
    http.get('/i18n/en.json').subscribe();
    const req = httpMock.expectOne('/i18n/en.json');
    expect(req.request.headers.has('X-Requested-With')).toBe(false);
    req.flush({});
  });

  it('clears the session and routes to /login on a mid-session 401', () => {
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    http.get('/api/issuers').subscribe({ error: () => undefined });
    httpMock
      .expectOne('/api/issuers')
      .flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });

    expect(session.clear).toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(['/login']);
  });

  it('does not redirect on the /api/me probe 401', () => {
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    http.get('/api/me').subscribe({ error: () => undefined });
    httpMock
      .expectOne('/api/me')
      .flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });

    expect(session.clear).not.toHaveBeenCalled();
    expect(navigate).not.toHaveBeenCalled();
  });
});
