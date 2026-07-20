// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Vite build config for the admin console.
//
// base is /admin/ because the in process IronAuth server embeds the built dist
// (rust-embed, crates/ironauth-admin-ui) and mounts it under /admin on the
// public plane, so every built asset URL must be prefixed. A standalone deploy
// that serves the app at the site root rebuilds with base "/".
//
// The build is configured so the served Content Security Policy needs no
// unsafe-inline: assets are content hashed and external (assetsInlineLimit 0),
// the module preload polyfill (which Vite would otherwise inline) is disabled,
// and the styles ship as one external stylesheet rather than an inline block.
import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

export default defineConfig({
  base: "/admin/",
  plugins: [preact()],
  build: {
    assetsInlineLimit: 0,
    modulePreload: false,
    cssCodeSplit: false,
  },
});
