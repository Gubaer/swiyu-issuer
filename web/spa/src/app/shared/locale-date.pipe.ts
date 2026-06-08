import { Pipe, PipeTransform, inject } from '@angular/core';
import { TranslocoService } from '@jsverse/transloco';

// Renders an ISO-8601 instant (as sent by the API, e.g. "2026-06-08T14:55:01Z")
// in the active UI language using the platform's Intl locale data: German ->
// "8. Juni 2026 16:55", English -> "June 8, 2026 16:55". The time is shown in
// the viewer's local timezone; the raw UTC literal is meant to be shown
// verbatim on hover (bind the same value to pTooltip alongside).
//
// Date and time are formatted as separate Intl parts and joined with a space so
// the output omits the locale's verbose connector ("um" / "at").
//
// The pipe is pure and reads the active language once per (value, lang) pair.
// The app has no runtime language switcher today; if one is added, pass the
// active lang as an argument (`date | localeDate: lang()`) so the pipe re-runs
// when it changes, or make the pipe impure.
@Pipe({ name: 'localeDate', standalone: true })
export class LocaleDatePipe implements PipeTransform {
  private readonly transloco = inject(TranslocoService);

  transform(value: string | null | undefined, lang?: string): string {
    if (!value) {
      return '';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      // Not a parseable instant; surface the original rather than "Invalid Date".
      return value;
    }
    const locale = lang ?? this.transloco.getActiveLang();
    const datePart = new Intl.DateTimeFormat(locale, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    }).format(date);
    const timePart = new Intl.DateTimeFormat(locale, {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(date);
    return `${datePart} ${timePart}`;
  }
}
