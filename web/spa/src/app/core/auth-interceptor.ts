import { inject } from '@angular/core';
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

import { SessionService } from './session-service';

/** The session probe; its own 401 is the expected "not logged in" answer. */
const ME_PROBE = '/api/me';

/**
 * For `/api/*` requests: add the `X-Requested-With` header (the CSRF custom-header
 * signal the BFF requires), and on a mid-session `401` clear the cached session
 * and route to `/login`. The `/api/me` probe is exempt from the redirect — its
 * 401 is the normal unauthenticated answer that `SessionService` already handles.
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith('/api/')) {
    return next(req);
  }

  const router = inject(Router);
  const session = inject(SessionService);

  const withCsrfHeader = req.clone({
    setHeaders: { 'X-Requested-With': 'XMLHttpRequest' },
  });

  return next(withCsrfHeader).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401 && req.url !== ME_PROBE) {
        session.clear();
        void router.navigate(['/login']);
      }
      return throwError(() => error);
    }),
  );
};
