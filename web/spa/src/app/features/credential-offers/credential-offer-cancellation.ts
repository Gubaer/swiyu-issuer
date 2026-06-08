import { Injectable, inject } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { TranslocoService } from '@jsverse/transloco';
import { ConfirmationService, MessageService } from 'primeng/api';

import { CredentialOfferSummary, CredentialOffersService } from './credential-offers-service';

export interface CancelCallbacks {
  // Patch local state with the cancellation timestamp from the response.
  onCancelled: (cancelledAt: string | null) => void;
  // The offer left the pending state between render and click (HTTP 409);
  // callers typically resync from the server here.
  onConflict?: () => void;
}

// Shared cancel-confirmation flow for credential offers: the confirmation
// dialog, the cancel API call, and the success/error toasts live here once.
// The list (patch the table row) and the detail page (patch the loaded offer)
// differ only in their callbacks. The confirmation renders through the global
// `<p-confirmDialog />` host at the app root.
@Injectable({ providedIn: 'root' })
export class CredentialOfferCancellation {
  private readonly service = inject(CredentialOffersService);
  private readonly confirmation = inject(ConfirmationService);
  private readonly messages = inject(MessageService);
  private readonly transloco = inject(TranslocoService);

  confirm(
    issuerId: string,
    offer: Pick<CredentialOfferSummary, 'id' | 'state'>,
    callbacks: CancelCallbacks,
  ): void {
    if (offer.state !== 'pending') {
      return;
    }
    this.confirmation.confirm({
      header: this.t('credential_offer.cancel.confirm_header'),
      message: this.t('credential_offer.cancel.confirm_message', { id: offer.id }),
      icon: 'pi pi-exclamation-triangle',
      acceptButtonProps: {
        label: this.t('credential_offer.cancel.confirm_accept'),
        severity: 'danger',
      },
      rejectButtonProps: {
        label: this.t('credential_offer.cancel.confirm_reject'),
        severity: 'secondary',
        outlined: true,
      },
      accept: () => {
        this.service.cancel(issuerId, offer.id).subscribe({
          next: (updated) => {
            callbacks.onCancelled(updated.cancelled_at);
            this.messages.add({
              severity: 'success',
              detail: this.t('credential_offer.cancel.success'),
            });
          },
          error: (err: HttpErrorResponse) => {
            if (err.status === 409) {
              callbacks.onConflict?.();
            }
            this.messages.add({
              severity: 'error',
              detail: this.t('credential_offer.cancel.error'),
            });
          },
        });
      },
    });
  }

  private t(key: string, params?: Record<string, unknown>): string {
    return this.transloco.translate(key, params);
  }
}
