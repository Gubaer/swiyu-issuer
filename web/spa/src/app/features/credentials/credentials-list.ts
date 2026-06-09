import { Component, computed, effect, inject, signal, untracked, viewChild } from '@angular/core';
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

import { LocaleDatePipe } from '../../shared/locale-date.pipe';
import { Issuer } from '../issuers/issuers-service';
import { IssuersStore } from '../issuers/issuers-store';
import { CredentialLifecycle } from './credential-lifecycle';
import { Credential, CredentialState } from './credentials-service';
import { CredentialsStore } from './credentials-store';

@Component({
  selector: 'app-credentials-list',
  standalone: true,
  imports: [
    FormsModule,
    RouterLink,
    TranslocoPipe,
    LocaleDatePipe,
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
  templateUrl: './credentials-list.html',
  styleUrl: './credentials-list.scss',
})
export class CredentialsList {
  private readonly issuersStore = inject(IssuersStore);
  private readonly credentialsStore = inject(CredentialsStore);
  private readonly lifecycle = inject(CredentialLifecycle);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly transloco = inject(TranslocoService);

  protected readonly issuers = this.issuersStore.issuers;
  protected readonly issuersLoading = this.issuersStore.listLoading;
  protected readonly issuersError = this.issuersStore.listError;

  protected readonly credentials = this.credentialsStore.items;
  protected readonly credentialsLoading = this.credentialsStore.loading;
  protected readonly credentialsError = this.credentialsStore.error;
  protected readonly hasMore = this.credentialsStore.hasMore;

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

    // Drive the credentials store from the current selection. `loadFor` resets
    // state every call, so this is also what clears the table when the
    // selection is cleared (the load just runs against `null`-guarded code).
    effect(() => {
      const issuer = this.selectedIssuer();
      if (!issuer) {
        untracked(() => this.credentialsStore.clear());
        return;
      }
      untracked(() => this.credentialsStore.loadFor(issuer.id));
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

  protected refreshCredentials(): void {
    this.credentialsStore.refresh();
  }

  protected loadMoreCredentials(): void {
    this.credentialsStore.loadMore();
  }

  // Build the menu model for this row, then open it under the trigger. Built on
  // click so the labels are translated after the language file has loaded. Each
  // item stays visible but disabled when its transition is not legal for the
  // row's current state.
  protected openRowMenu(event: Event, credential: Credential): void {
    this.menuItems.set([
      {
        label: this.t('credential.lifecycle.suspend_action'),
        icon: 'pi pi-pause',
        disabled: credential.state !== 'active',
        command: () => this.suspend(credential),
      },
      {
        label: this.t('credential.lifecycle.resume_action'),
        icon: 'pi pi-play',
        disabled: credential.state !== 'suspended',
        command: () => this.resume(credential),
      },
      {
        label: this.t('credential.lifecycle.revoke_action'),
        icon: 'pi pi-ban',
        disabled: credential.state === 'revoked',
        command: () => this.revoke(credential),
      },
    ]);
    this.rowMenu().toggle(event);
  }

  private suspend(credential: Credential): void {
    const issuer = this.selectedIssuer();
    if (!issuer) {
      return;
    }
    this.lifecycle.suspend(issuer.id, credential, this.rowCallbacks());
  }

  private resume(credential: Credential): void {
    const issuer = this.selectedIssuer();
    if (!issuer) {
      return;
    }
    this.lifecycle.resume(issuer.id, credential, this.rowCallbacks());
  }

  private revoke(credential: Credential): void {
    const issuer = this.selectedIssuer();
    if (!issuer) {
      return;
    }
    this.lifecycle.revoke(issuer.id, credential, this.rowCallbacks());
  }

  // On success patch the row in place; on conflict (the state changed between
  // render and click) resync from the server.
  private rowCallbacks() {
    return {
      onUpdated: (updated: Credential) => this.credentialsStore.applyUpdate(updated),
      onConflict: () => this.credentialsStore.refresh(),
    };
  }

  protected stateSeverity(state: CredentialState): 'success' | 'warn' | 'danger' {
    switch (state) {
      case 'active':
        return 'success';
      case 'suspended':
        return 'warn';
      case 'revoked':
        return 'danger';
    }
  }

  protected trackByCredentialId(_index: number, credential: Credential): string {
    return credential.id;
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
