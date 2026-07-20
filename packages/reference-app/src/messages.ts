// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The i18n seam. The server sends a stable numeric message id (the localization
// key) with every label, hint, and error, plus the default English text as a
// convenience. This app keys its copy on the id: MESSAGE_TEXT (generated from
// docs/flow-messages.json) is the default-locale fallback, and a fork localizes
// by supplying an overrides map for a locale WITHOUT touching render logic. The
// server-supplied text is the last resort, so a brand-new id the app has not yet
// localized still renders sane copy.

import type { Message } from "./contract/flow.gen.js";
import { MESSAGE_TEXT } from "./contract/messages.gen.js";

export type LocaleOverrides = Readonly<Record<number, string>>;

export class Copy {
  private readonly overrides: LocaleOverrides;

  constructor(overrides: LocaleOverrides = {}) {
    this.overrides = overrides;
  }

  // Resolve a message to display text, preferring a localized override, then the
  // generated default-locale copy, then the text the server shipped. Returns a
  // plain string that the caller renders via textContent (never innerHTML).
  text(message: Message): string {
    return (
      this.overrides[message.id] ??
      MESSAGE_TEXT[message.id] ??
      message.text
    );
  }
}
