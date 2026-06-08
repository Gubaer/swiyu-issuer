import { TestBed } from '@angular/core/testing';
import {
  ActivatedRouteSnapshot,
  Router,
  RouterStateSnapshot,
  UrlTree,
  provideRouter,
} from '@angular/router';

import { authGuard } from './auth-guard';
import { SessionService } from './session-service';

function run(authenticated: boolean, url: string) {
  const session = {
    load: vi.fn().mockResolvedValue(undefined),
    isAuthenticated: vi.fn().mockReturnValue(authenticated),
  };
  TestBed.configureTestingModule({
    providers: [provideRouter([]), { provide: SessionService, useValue: session }],
  });
  const result = TestBed.runInInjectionContext(() =>
    authGuard({} as ActivatedRouteSnapshot, { url } as RouterStateSnapshot),
  );
  return { result, session };
}

describe('authGuard', () => {
  it('loads the session and allows an authenticated user', async () => {
    const { result, session } = run(true, '/issuers');
    expect(await result).toBe(true);
    expect(session.load).toHaveBeenCalled();
  });

  it('redirects to /login with return_to when unauthenticated', async () => {
    const { result } = run(false, '/issuers');
    const tree = (await result) as UrlTree;
    const router = TestBed.inject(Router);
    expect(router.serializeUrl(tree)).toBe('/login?return_to=%2Fissuers');
  });
});
