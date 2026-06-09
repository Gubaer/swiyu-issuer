import { Injectable, inject } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import { TranslocoService } from '@jsverse/transloco';
import { ConfirmationService, MessageService } from 'primeng/api';

import { Credential, CredentialsService } from './credentials-service';

export interface LifecycleCallbacks {
  // Patch local state with the full updated record from the response.
  onUpdated: (updated: Credential) => void;
  // The credential left the expected state between render and click (HTTP 409);
  // callers typically resync from the server here.
  onConflict?: () => void;
}

// Shared lifecycle flow for issued credentials: the suspend/resume/revoke API
// calls, the revoke confirmation dialog, and the success/error toasts live here
// once. The list (patch the table row) and the detail page (patch the loaded
// credential) differ only in their callbacks. Suspend and resume are reversible
// and apply immediately; revoke is permanent (UC05) and confirms first via the
// global `<p-confirmDialog />` host at the app root.
@Injectable({ providedIn: 'root' })
export class CredentialLifecycle {
  private readonly service = inject(CredentialsService);
  private readonly confirmation = inject(ConfirmationService);
  private readonly messages = inject(MessageService);
  private readonly transloco = inject(TranslocoService);

  suspend(
    issuerId: string,
    credential: Pick<Credential, 'id' | 'state'>,
    callbacks: LifecycleCallbacks,
  ): void {
    if (credential.state !== 'active') {
      return;
    }
    this.run(this.service.suspend(issuerId, credential.id), 'suspend', callbacks);
  }

  resume(
    issuerId: string,
    credential: Pick<Credential, 'id' | 'state'>,
    callbacks: LifecycleCallbacks,
  ): void {
    if (credential.state !== 'suspended') {
      return;
    }
    this.run(this.service.resume(issuerId, credential.id), 'resume', callbacks);
  }

  revoke(
    issuerId: string,
    credential: Pick<Credential, 'id' | 'state'>,
    callbacks: LifecycleCallbacks,
  ): void {
    if (credential.state !== 'active' && credential.state !== 'suspended') {
      return;
    }
    this.confirmation.confirm({
      header: this.t('credential.lifecycle.revoke_confirm_header'),
      message: this.t('credential.lifecycle.revoke_confirm_message', { id: credential.id }),
      icon: 'pi pi-exclamation-triangle',
      acceptButtonProps: {
        label: this.t('credential.lifecycle.revoke_confirm_accept'),
        severity: 'danger',
      },
      rejectButtonProps: {
        label: this.t('credential.lifecycle.revoke_confirm_reject'),
        severity: 'secondary',
        outlined: true,
      },
      accept: () => {
        this.run(this.service.revoke(issuerId, credential.id), 'revoke', callbacks);
      },
    });
  }

  // Subscribe to a lifecycle call, patch local state and toast on success, and
  // surface a conflict callback plus an error toast on failure. The `action`
  // selects the i18n success/error keys (`credential.lifecycle.<action>_*`).
  private run(
    call: Observable<Credential>,
    action: 'suspend' | 'resume' | 'revoke',
    callbacks: LifecycleCallbacks,
  ): void {
    call.subscribe({
      next: (updated) => {
        callbacks.onUpdated(updated);
        this.messages.add({
          severity: 'success',
          detail: this.t(`credential.lifecycle.${action}_success`),
        });
      },
      error: (err: HttpErrorResponse) => {
        if (err.status === 409) {
          callbacks.onConflict?.();
        }
        this.messages.add({
          severity: 'error',
          detail: this.t(`credential.lifecycle.${action}_error`),
        });
      },
    });
  }

  private t(key: string, params?: Record<string, unknown>): string {
    return this.transloco.translate(key, params);
  }
}
