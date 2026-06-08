import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { TranslocoPipe, TranslocoService } from '@jsverse/transloco';
import { MenuItem } from 'primeng/api';
import { MenuModule } from 'primeng/menu';
import { StyleClassModule } from 'primeng/styleclass';
import { AppConfigurator } from './app.configurator';
import { LayoutService } from '@/app/layout/service/layout.service';
import { Account, SessionService } from '@/app/core/session-service';

@Component({
  selector: 'app-topbar',
  standalone: true,
  imports: [RouterModule, CommonModule, StyleClassModule, MenuModule, TranslocoPipe, AppConfigurator],
  template: `<div class="layout-topbar">
    <div class="layout-topbar-logo-container">
      <button class="layout-menu-button layout-topbar-action" (click)="layoutService.onMenuToggle()">
        <i class="pi pi-bars"></i>
      </button>
      <a class="layout-topbar-logo" routerLink="/">
        <i class="pi pi-id-card text-primary" style="font-size: 1.5rem"></i>
        <span>swiyu issuer</span>
      </a>
    </div>

    <div class="layout-topbar-actions">
      @if (session.me(); as me) {
        <button
          type="button"
          class="layout-topbar-action"
          [attr.aria-label]="'topbar.account' | transloco"
          (click)="userMenu.toggle($event)"
        >
          <span class="layout-topbar-user hidden md:inline-block">
            {{ me.selected_account.display_name }} &#64; {{ tenantLabel(me.selected_account) }}
          </span>
          <i class="pi pi-user"></i>
        </button>
        <p-menu #userMenu [model]="menuItems()" [popup]="true" appendTo="body" />
      }

      <div class="layout-config-menu">
        <button type="button" class="layout-topbar-action" (click)="toggleDarkMode()">
          <i [ngClass]="{ 'pi ': true, 'pi-moon': layoutService.isDarkTheme(), 'pi-sun': !layoutService.isDarkTheme() }"></i>
        </button>
        <div class="relative">
          <button
            class="layout-topbar-action layout-topbar-action-highlight"
            pStyleClass="@next"
            enterFromClass="hidden"
            enterActiveClass="animate-scalein"
            leaveToClass="hidden"
            leaveActiveClass="animate-fadeout"
            [hideOnOutsideClick]="true"
          >
            <i class="pi pi-palette"></i>
          </button>
          <app-configurator />
        </div>
      </div>
    </div>
  </div>`
})
export class AppTopbar {
  layoutService = inject(LayoutService);
  protected readonly session = inject(SessionService);
  private readonly transloco = inject(TranslocoService);

  /** The popup-menu model: account switcher (when >1) + logout. */
  protected readonly menuItems = computed<MenuItem[]>(() => {
    const me = this.session.me();
    if (!me) {
      return [];
    }

    const items: MenuItem[] = [];
    if (me.accounts.length > 1) {
      items.push({
        label: this.transloco.translate('topbar.switch_account'),
        items: me.accounts.map((account) => ({
          label: `${account.display_name} @ ${this.tenantLabel(account)}`,
          icon: account.id === me.selected_account.id ? 'pi pi-check' : 'pi pi-user',
          disabled: account.id === me.selected_account.id,
          command: () => this.switchAccount(account.id),
        })),
      });
    }
    items.push({
      label: this.transloco.translate('topbar.logout'),
      icon: 'pi pi-sign-out',
      command: () => this.logout(),
    });
    return items;
  });

  protected tenantLabel(account: Account): string {
    return account.tenant_display_name ?? account.tenant_id;
  }

  private switchAccount(accountId: string): void {
    void this.session.selectAccount(accountId).then(() => {
      // Full reload so every data view reflects the new account/tenant.
      window.location.reload();
    });
  }

  /** Single sign-out: a full-page nav (the BFF 302s to the realm end-session). */
  private logout(): void {
    window.location.href = '/api/auth/logout';
  }

  toggleDarkMode() {
    this.layoutService.layoutConfig.update((state) => ({
      ...state,
      darkTheme: !state.darkTheme
    }));
  }
}
