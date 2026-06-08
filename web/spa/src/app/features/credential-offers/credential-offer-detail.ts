import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import hljs from 'highlight.js/lib/core';
import json from 'highlight.js/lib/languages/json';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { MessageModule } from 'primeng/message';
import { TagModule } from 'primeng/tag';

import { CredentialOfferCancellation } from './credential-offer-cancellation';
import {
  CredentialOffer,
  CredentialOfferState,
  CredentialOffersService,
} from './credential-offers-service';

hljs.registerLanguage('json', json);

@Component({
  selector: 'app-credential-offer-detail',
  standalone: true,
  imports: [
    RouterLink,
    TranslocoPipe,
    ButtonModule,
    CardModule,
    ConfirmDialogModule,
    MessageModule,
    TagModule,
  ],
  templateUrl: './credential-offer-detail.html',
  styleUrl: './credential-offer-detail.scss',
})
export class CredentialOfferDetail implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly service = inject(CredentialOffersService);
  private readonly cancellation = inject(CredentialOfferCancellation);

  // The issuer id is needed for every API call; it rides along as a query
  // param on the link from the list (the offer summary carries `issuer_id`).
  protected readonly issuerId = signal<string | null>(null);
  protected readonly offer = signal<CredentialOffer | null>(null);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  // Claims are present only while the offer is pending; once the holder
  // redeems it they are removed from the database. Treat an empty/absent
  // object as "no longer available".
  protected readonly hasClaims = computed(() => {
    const claims = this.offer()?.claims;
    return !!claims && Object.keys(claims).length > 0;
  });

  // Syntax-highlighted claims JSON. highlight.js escapes its input, so the
  // output is safe to bind via [innerHTML].
  protected readonly highlightedClaims = computed(() => {
    const claims = this.offer()?.claims;
    if (!claims) {
      return '';
    }
    const text = JSON.stringify(claims, null, 2);
    return hljs.highlight(text, { language: 'json' }).value;
  });

  ngOnInit(): void {
    const offerId = this.route.snapshot.paramMap.get('offerId');
    const issuerId = this.route.snapshot.queryParamMap.get('issuerId');
    this.issuerId.set(issuerId);
    if (!offerId || !issuerId) {
      this.error.set('credential_offer.detail.load_error');
      this.loading.set(false);
      return;
    }
    this.service.get(issuerId, offerId).subscribe({
      next: (offer) => {
        this.offer.set(offer);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('credential_offer.detail.load_error');
        this.loading.set(false);
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

  // Cancel the offer via the shared confirmation flow. On success patch the
  // loaded offer; on conflict (already issued/cancelled) reload to show truth.
  protected cancel(): void {
    const offer = this.offer();
    const issuerId = this.issuerId();
    if (!offer || !issuerId) {
      return;
    }
    this.cancellation.confirm(issuerId, offer, {
      onCancelled: (cancelledAt) =>
        this.offer.update((current) =>
          current ? { ...current, state: 'cancelled', cancelled_at: cancelledAt } : current,
        ),
      onConflict: () => this.reload(issuerId, offer.id),
    });
  }

  private reload(issuerId: string, offerId: string): void {
    this.service.get(issuerId, offerId).subscribe({
      next: (offer) => this.offer.set(offer),
    });
  }
}
