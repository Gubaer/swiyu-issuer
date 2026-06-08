import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { SessionService } from './session-service';

/**
 * Ensures the session is loaded before activating a guarded route. When the user
 * is not authenticated, redirects to `/login` carrying the attempted URL as
 * `return_to` so the BFF can send them back after login.
 */
export const authGuard: CanActivateFn = async (_route, state) => {
  const session = inject(SessionService);
  const router = inject(Router);

  await session.load();
  if (session.isAuthenticated()) {
    return true;
  }
  return router.createUrlTree(['/login'], { queryParams: { return_to: state.url } });
};
