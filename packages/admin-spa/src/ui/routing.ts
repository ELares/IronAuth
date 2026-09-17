// SPDX-License-Identifier: MIT OR Apache-2.0

// Keep console navigation inside the embedded mount. Standalone deployments
// and component tests at the origin root retain their existing route paths.
export function consoleHref(path: string): string {
  const embedded =
    window.location.pathname === "/admin" ||
    window.location.pathname.startsWith("/admin/");
  return embedded ? `/admin${path}` : path;
}
