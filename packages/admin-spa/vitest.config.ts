// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Vitest config for the admin console unit and component tests (issue #90, PR 3).
// Tests live under test/ (OUTSIDE src/) so the strict app tsconfig and the Vite
// production bundle never include them; the route audit and the app typecheck
// stay app only. The preact preset gives the tests the same JSX transform the app
// uses, and jsdom supplies the DOM the component tests render into.
import { defineConfig } from "vitest/config";
import preact from "@preact/preset-vite";

export default defineConfig({
  plugins: [preact()],
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.ts", "test/**/*.test.tsx"],
  },
});
