import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';

import { Login } from './login';

/** Access to the component's protected, test-relevant members. */
interface Internals {
  errorKey: string | null;
  loginUrl(): string;
}

function makeLogin(params: Record<string, string>): Internals {
  TestBed.configureTestingModule({
    providers: [
      {
        provide: ActivatedRoute,
        useValue: { snapshot: { queryParamMap: convertToParamMap(params) } },
      },
    ],
  });
  // Instantiate the class only (no template render → no Transloco needed).
  return TestBed.runInInjectionContext(() => new Login()) as unknown as Internals;
}

describe('Login', () => {
  it('has no error message without an ?error= param', () => {
    expect(makeLogin({}).errorKey).toBeNull();
  });

  it('maps a known ?error= code to its message key', () => {
    expect(makeLogin({ error: 'no_access' }).errorKey).toBe('auth.login.error_no_access');
  });

  it('maps an unknown ?error= code to the generic message', () => {
    expect(makeLogin({ error: 'something-else' }).errorKey).toBe('auth.login.error_generic');
  });

  it('builds the login URL with an encoded return_to', () => {
    expect(makeLogin({ return_to: '/issuers' }).loginUrl()).toBe(
      '/api/auth/login?return_to=%2Fissuers',
    );
  });

  it('defaults return_to to / when absent', () => {
    expect(makeLogin({}).loginUrl()).toBe('/api/auth/login?return_to=%2F');
  });
});
