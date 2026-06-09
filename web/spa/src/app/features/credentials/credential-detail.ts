import { Component, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { MessageModule } from 'primeng/message';
import { TagModule } from 'primeng/tag';
import { TooltipModule } from 'primeng/tooltip';

import { LocaleDatePipe } from '../../shared/locale-date.pipe';
import { CredentialLifecycle } from './credential-lifecycle';
import { Credential, CredentialState, CredentialsService } from './credentials-service';

@Component({
  selector: 'app-credential-detail',
  standalone: true,
  imports: [
    RouterLink,
    TranslocoPipe,
    LocaleDatePipe,
    ButtonModule,
    CardModule,
    ConfirmDialogModule,
    MessageModule,
    TagModule,
    TooltipModule,
  ],
  templateUrl: './credential-detail.html',
  styleUrl: './credential-detail.scss',
})
export class CredentialDetail implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly service = inject(CredentialsService);
  private readonly lifecycle = inject(CredentialLifecycle);

  // The issuer id is needed for every API call; it rides along as a query
  // param on the link from the list (the credential carries `issuer_id`).
  protected readonly issuerId = signal<string | null>(null);
  protected readonly credential = signal<Credential | null>(null);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    const credentialId = this.route.snapshot.paramMap.get('id');
    const issuerId = this.route.snapshot.queryParamMap.get('issuerId');
    this.issuerId.set(issuerId);
    if (!credentialId || !issuerId) {
      this.error.set('credential.detail.load_error');
      this.loading.set(false);
      return;
    }
    this.service.get(issuerId, credentialId).subscribe({
      next: (credential) => {
        this.credential.set(credential);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('credential.detail.load_error');
        this.loading.set(false);
      },
    });
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

  // Each action delegates to the shared lifecycle flow. On success patch the
  // loaded credential with the server's record; on conflict (the state changed
  // between render and click) reload to show the truth.
  protected suspend(): void {
    this.runAction((issuerId, credential, cb) => this.lifecycle.suspend(issuerId, credential, cb));
  }

  protected resume(): void {
    this.runAction((issuerId, credential, cb) => this.lifecycle.resume(issuerId, credential, cb));
  }

  protected revoke(): void {
    this.runAction((issuerId, credential, cb) => this.lifecycle.revoke(issuerId, credential, cb));
  }

  private runAction(
    action: (
      issuerId: string,
      credential: Credential,
      callbacks: {
        onUpdated: (updated: Credential) => void;
        onConflict: () => void;
      },
    ) => void,
  ): void {
    const credential = this.credential();
    const issuerId = this.issuerId();
    if (!credential || !issuerId) {
      return;
    }
    action(issuerId, credential, {
      onUpdated: (updated) => this.credential.set(updated),
      onConflict: () => this.reload(issuerId, credential.id),
    });
  }

  private reload(issuerId: string, credentialId: string): void {
    this.service.get(issuerId, credentialId).subscribe({
      next: (credential) => this.credential.set(credential),
    });
  }
}
