import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { MessageModule } from 'primeng/message';

/** The `?error=` codes the BFF redirects back with on a failed login. */
const KNOWN_ERRORS = ['no_access', 'idp', 'state', 'unavailable'];

@Component({
  selector: 'app-login',
  imports: [TranslocoPipe, ButtonModule, CardModule, MessageModule],
  templateUrl: './login.html',
  styleUrl: './login.scss'
})
export class Login {
  private readonly params = inject(ActivatedRoute).snapshot.queryParamMap;

  /** Transloco key for the `?error=` message, or `null` when there is none. */
  protected readonly errorKey: string | null = (() => {
    const error = this.params.get('error');
    if (!error) {
      return null;
    }
    return `auth.login.error_${KNOWN_ERRORS.includes(error) ? error : 'generic'}`;
  })();

  /**
   * Starts the login handshake. A full-page navigation (not an Angular route or
   * XHR) because the BFF responds with a cross-origin 302 to the realm.
   */
  protected signIn(): void {
    window.location.href = this.loginUrl();
  }

  /** The BFF login URL carrying the validated `return_to`. */
  protected loginUrl(): string {
    const returnTo = this.params.get('return_to') ?? '/';
    return `/api/auth/login?return_to=${encodeURIComponent(returnTo)}`;
  }
}
