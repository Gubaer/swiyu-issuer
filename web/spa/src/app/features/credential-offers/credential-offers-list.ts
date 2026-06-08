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
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { TranslocoPipe, TranslocoService } from '@jsverse/transloco';
import { map } from 'rxjs';
import { MenuItem } from 'primeng/api';
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
import { CredentialOfferCancellation } from './credential-offer-cancellation';
import { CredentialOfferState, CredentialOfferSummary } from './credential-offers-service';
import { CredentialOffersStore } from './credential-offers-store';

@Component({
  selector: 'app-credential-offers-list',
  standalone: true,
  imports: [
    FormsModule,
    RouterLink,
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
  private readonly cancellation = inject(CredentialOfferCancellation);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly transloco = inject(TranslocoService);

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

  // The row action menu is a single shared popup. Its model is rebuilt for the
  // clicked row in `openRowMenu` rather than via a computed: building it eagerly
  // would call `translate()` before transloco has loaded the language file,
  // yielding a "missing translation" for the label that never recovers.
  private readonly rowMenu = viewChild.required<Menu>('rowMenu');
  protected readonly menuItems = signal<MenuItem[]>([]);

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

  // Build the menu model for this row, then open it under the trigger. Built on
  // click so the label is translated after the language file has loaded.
  protected openRowMenu(event: Event, offer: CredentialOfferSummary): void {
    this.menuItems.set([
      {
        label: this.t('credential_offer.cancel.action'),
        icon: 'pi pi-times',
        // Only pending offers can be cancelled; the item stays visible but
        // disabled otherwise.
        disabled: offer.state !== 'pending',
        command: () => this.confirmCancel(offer),
      },
    ]);
    this.rowMenu().toggle(event);
  }

  // Cancel the offer via the shared confirmation flow. On success patch the row
  // in place; on conflict (already issued/cancelled) resync from the server.
  private confirmCancel(offer: CredentialOfferSummary): void {
    const issuer = this.selectedIssuer();
    if (!issuer) {
      return;
    }
    this.cancellation.confirm(issuer.id, offer, {
      onCancelled: (cancelledAt) => this.offersStore.markCancelled(offer.id, cancelledAt),
      onConflict: () => this.offersStore.refresh(),
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
