// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The diagnostics ENTRY POINT (issue #90, PR 7). PR7 wires the nav and route
// seam only: the diagnostic CONTENT (the connector health matrix, the live
// federation reads, the token and session introspection views) lands in the
// follow up issue #91. This placeholder is deliberately inert: it holds NO
// network call and NO path, so #91 drops its real reads in behind this same route
// without moving the entry point. Keeping the seam here now means the nav item,
// the palette command, and the route all exist and stay stable across that change.

export function DiagnosticsView() {
  return (
    <section class="placeholder" aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">Diagnostics</h2>
      <p>
        The diagnostics surface (connector health, live federation reads, token
        and session introspection) is being built under issue #91. This entry
        point is wired now so the navigation and route are stable; the content
        lands with that change.
      </p>
    </section>
  );
}
