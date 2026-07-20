// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The admin console entry point. Vite bundles from here into content hashed,
// external assets (no inline script or style), which is what keeps the served
// Content Security Policy free of unsafe-inline. The stylesheet is imported so
// Vite emits it as one external, hashed file rather than an inline block.

import { render } from "preact";
import { App } from "./app";
import "./style.css";

const root = document.getElementById("app");
if (root) {
  render(<App />, root);
}
