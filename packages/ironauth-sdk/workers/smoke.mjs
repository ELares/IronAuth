// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The Cloudflare Workers portability smoke (issue #115).
 *
 * The SAME checks the other lanes run, executed inside workerd. A `node:` import or a
 * Node-only global fails at module load here, which is the failure the Node suite
 * structurally cannot see.
 */

import { EXPECTED_CHECKS, runChecks } from './checks.mjs';

export default {
  async fetch() {
    const result = await runChecks();
    const short = result.count !== EXPECTED_CHECKS;
    return new Response(JSON.stringify({ ...result, expected: EXPECTED_CHECKS, short }), {
      status: result.ok && !short ? 200 : 500,
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
