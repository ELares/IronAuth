// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The CLI entry for the Node, Deno and Bun portability lanes (issue #115).
 *
 * Exits non-zero on any failed check AND on a short count, so a lane cannot pass by running
 * fewer checks than exist.
 */

import { EXPECTED_CHECKS, runChecks } from './checks.mjs';

const result = await runChecks();
console.log(JSON.stringify(result));
if (!result.ok) {
  console.error(`failed: ${result.failed.join(', ')}`);
  // `process` does not exist on every runtime; throwing is the portable non-zero exit.
  throw new Error('portability checks failed');
}
if (result.count !== EXPECTED_CHECKS) {
  throw new Error(`ran ${result.count} checks, expected ${EXPECTED_CHECKS}`);
}
