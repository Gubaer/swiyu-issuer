import {
  Component,
  computed,
  effect,
  inject,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { HttpErrorResponse } from '@angular/common/http';
import { ActivatedRoute, Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { TranslocoPipe, TranslocoService } from '@jsverse/transloco';
import { map } from 'rxjs';
import { ConfirmationService, MenuItem, MessageService } from 'primeng/api';
import { AutoCompleteModule, AutoCompleteCompleteEvent } from 'primeng/autocomplete';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';
import { ButtonModule } from 'primeng/button';
import { TooltipModule } from 'primeng/tooltip';
import { MessageModule } from 'primeng/message';
import { Menu, MenuModule } from 'primeng/menu';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ProgressSpinnerModule } from 'primeng/progressspinner';

import { Issuer } from '../issuers/issuers-service';
import { IssuersStore } from '../issuers/issuers-store';
import {
  CredentialOfferState,
  CredentialOfferSummary,
  CredentialOffersService,
} from './credential-offers-service';
import { CredentialOffersStore } from './credential-offers-store';

@Component({
  selector: 'app-credential-offers-list',
  standalone: true,
  imports: [
    FormsModule,
    TranslocoPipe,
    AutoCompleteModule,
    TableModule,
    TagModule,
    ButtonModule,
    TooltipModule,
    MessageModule,
    MenuModule,
    ConfirmDialogModule,
    ProgressSpinnerModule,
  ],
  templateUrl: './credential-offers-list.html',
  styleUrl: './credential-offers-list.scss',
})
export class CredentialOffersList {
  private readonly issuersStore = inject(IssuersStore);
  private readonly offersStore = inject(CredentialOffersStore);
  private readonly offersService = inject(CredentialOffersService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly transloco = inject(TranslocoService);
  private readonly confirmation = inject(ConfirmationService);
  private readonly messages = inject(MessageService);

  protected readonly issuers = this.issuersStore.issuers;
  protected readonly issuersLoading = this.issuersStore.listLoading;
  protected readonly issuersError = this.issuersStore.listError;

  protected readonly offers = this.offersStore.items;
  protected readonly offersLoading = this.offersStore.loading;
  protected readonly offersError = this.offersStore.error;
  protected readonly hasMore = this.offersStore.hasMore;

  // URL is the source of truth for the current selection. `selectedIssuer`
  // is a view onto (store list × ?issuerId=), and user picks write back to
  // the URL via `onIssuerChange`.
  private readonly issuerIdParam = toSignal(
    this.route.queryParamMap.pipe(map((p) => p.get('issuerId'))),
    { initialValue: null },
  );

  protected readonly selectedIssuer = computed<Issuer | null>(() => {
    const id = this.issuerIdParam();
    if (!id) {
      return null;
    }
    return this.issuers().find((issuer) => issuer.id === id) ?? null;
  });

  protected readonly issuerSuggestions = signal<Issuer[]>([]);

  // The row action menu is a single shared popup; `menuOffer` records which row
  // opened it so `menuItems` can build its model (and disable Cancel) for that
  // specific offer.
  private readonly rowMenu = viewChild.required<Menu>('rowMenu');
  protected readonly menuOffer = signal<CredentialOfferSummary | null>(null);
  protected readonly menuItems = computed<MenuItem[]>(() => {
    const offer = this.menuOffer();
    return [
      {
        label: this.t('credential_offer.list.cancel'),
        icon: 'pi pi-times',
        // Only pending offers can be cancelled; the item stays visible but
        // disabled otherwise.
        disabled: offer?.state !== 'pending',
        command: () => {
          if (offer) {
            this.confirmCancel(offer);
          }
        },
      },
    ];
  });

  constructor() {
    this.issuersStore.load();

    // If there is exactly one issuer and the URL doesn't already name one,
    // adopt it as the selection.
    effect(() => {
      if (this.issuersLoading()) {
        return;
      }
      if (this.issuerIdParam()) {
        return;
      }
      const list = this.issuers();
      if (list.length !== 1) {
        return;
      }
      const only = list[0];
      untracked(() => this.setIssuerInUrl(only.id, true));
    });

    // Drive the offers store from the current selection. `loadFor` resets
    // state every call, so this is also what clears the table when the
    // selection is cleared (the load just runs against `null`-guarded code).
    effect(() => {
      const issuer = this.selectedIssuer();
      if (!issuer) {
        untracked(() => this.offersStore.clear());
        return;
      }
      untracked(() => this.offersStore.loadFor(issuer.id));
    });
  }

  protected onIssuerChange(issuer: Issuer | null): void {
    this.setIssuerInUrl(issuer?.id ?? null, false);
  }

  protected searchIssuers(event: AutoCompleteCompleteEvent): void {
    const q = event.query.trim().toLowerCase();
    const all = this.issuers();
    if (q === '') {
      this.issuerSuggestions.set(all);
      return;
    }
    this.issuerSuggestions.set(
      all.filter(
        (issuer) =>
          issuer.display_name.toLowerCase().includes(q) || issuer.did.toLowerCase().includes(q),
      ),
    );
  }

  protected reloadIssuers(): void {
    this.issuersStore.load();
  }

  protected refreshOffers(): void {
    this.offersStore.refresh();
  }

  protected createOffer(): void {
    const issuer = this.selectedIssuer();
    this.router.navigate(['/credential-offers/new'], {
      queryParams: issuer ? { issuerId: issuer.id } : {},
    });
  }

  protected loadMoreOffers(): void {
    this.offersStore.loadMore();
  }

  // Point the shared row menu at this offer, then open it under the trigger.
  protected openRowMenu(event: Event, offer: CredentialOfferSummary): void {
    this.menuOffer.set(offer);
    this.rowMenu().toggle(event);
  }

  // Confirm, then cancel the offer via the BFF. On success patch the row in
  // place; on conflict (already issued/cancelled) resync from the server.
  private confirmCancel(offer: CredentialOfferSummary): void {
    const issuer = this.selectedIssuer();
    if (!issuer || offer.state !== 'pending') {
      return;
    }
    this.confirmation.confirm({
      header: this.t('credential_offer.list.cancel_confirm_header'),
      message: this.t('credential_offer.list.cancel_confirm_message', { id: offer.id }),
      icon: 'pi pi-exclamation-triangle',
      acceptButtonProps: {
        label: this.t('credential_offer.list.cancel_confirm_accept'),
        severity: 'danger',
      },
      rejectButtonProps: {
        label: this.t('credential_offer.list.cancel_confirm_reject'),
        severity: 'secondary',
        outlined: true,
      },
      accept: () => {
        this.offersService.cancel(issuer.id, offer.id).subscribe({
          next: (updated) => {
            this.offersStore.markCancelled(offer.id, updated.cancelled_at);
            this.messages.add({
              severity: 'success',
              detail: this.t('credential_offer.list.cancel_success'),
            });
          },
          error: (err: HttpErrorResponse) => {
            // 409 means the offer left the pending state between render and
            // click (e.g. it was just redeemed); refresh so the row is accurate.
            if (err.status === 409) {
              this.offersStore.refresh();
            }
            this.messages.add({
              severity: 'error',
              detail: this.t('credential_offer.list.cancel_error'),
            });
          },
        });
      },
    });
  }

  protected stateSeverity(state: CredentialOfferState): 'info' | 'success' | 'secondary' | 'warn' {
    switch (state) {
      case 'pending':
        return 'info';
      case 'issued':
        return 'success';
      case 'cancelled':
        return 'secondary';
      case 'expired':
        return 'warn';
    }
  }

  protected trackByOfferId(_index: number, offer: CredentialOfferSummary): string {
    return offer.id;
  }

  private setIssuerInUrl(id: string | null, replaceUrl: boolean): void {
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { issuerId: id },
      queryParamsHandling: 'merge',
      replaceUrl,
    });
  }

  private t(key: string, params?: Record<string, unknown>): string {
    return this.transloco.translate(key, params);
  }
}
