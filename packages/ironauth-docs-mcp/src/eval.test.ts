// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The integration-task eval (issue #123 criterion 1).
 *
 * > An agent completes a defined integration task (add IronAuth login to a sample app) using
 * > ONLY the docs MCP server and skills, in a recorded eval checked into the repo.
 *
 * # WHAT THIS MEASURES, AND WHAT IT DOES NOT
 *
 * It does not run a model. No LLM executes here, so this file cannot and does not claim that an
 * agent completed anything. Saying otherwise would be the easiest false claim in this
 * repository to make and the hardest for a reader to check.
 *
 * What it measures is the property the criterion actually depends on, and the one that decays:
 * **whether the docs MCP server, on its own, surfaces the guidance the task needs**. An eval
 * that ran a model would be measuring the model on the day it ran. This measures the corpus and
 * the retrieval, which are what change under us.
 *
 * The task is decomposed into the questions an agent has to answer to complete it, taken from
 * `docs/skills/integrate-ironauth.md` -- the skill an agent would be following. For each, the
 * eval asserts that `search_docs` surfaces a section containing the answer, and that the answer
 * is the CURRENT one rather than merely a plausible passage.
 *
 * When this fails, one of two things is true: the documentation stopped saying something it
 * used to, or retrieval stopped finding it. Both are exactly the failure that leaves an agent
 * confidently writing an integration from recall.
 *
 * # The eval is a table, and the table is the record
 *
 * `INTEGRATION_TASK` below IS the recorded eval: each row is a step, the query an agent would
 * issue, and the substring that proves the retrieved guidance is current. It is checked into the
 * repository and read by the test rather than described by it.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { DOCS_TOOLS, DocsMcpServer } from './server.js';

const corpus = readFileSync(
  new URL('../../../docs/llms-full.txt', import.meta.url),
  'utf8',
);
const server = new DocsMcpServer(corpus);

/** One step of the task: what an agent asks, and what the answer must contain. */
interface Step {
  readonly step: string;
  readonly query: string;
  /** A substring that must appear in a retrieved section. Chosen to be the CURRENT answer. */
  readonly answerContains: string;
  /** The document the answer should come from. */
  readonly expectedSource: string;
}

/**
 * THE RECORDED EVAL: adding IronAuth login to an app, step by step.
 *
 * Each `answerContains` is a phrase that is true today and would stop being true if the guidance
 * changed -- not a generic word that would match any version of the page. That is the difference
 * between an eval that notices a regression and one that passes forever.
 */
const INTEGRATION_TASK: readonly Step[] = [
  {
    step: 'Which architecture should a browser app use?',
    query: 'browser based apps architecture ranking backend for frontend',
    answerContains: 'Backend-for-frontend',
    expectedSource: 'docs/bff.md',
  },
  {
    step: 'May I store the token in localStorage?',
    query: 'localStorage token storage browser',
    answerContains: 'no supported way to store a token in `localStorage`',
    expectedSource: 'docs/bff.md',
  },
  {
    step: 'What cookie does the BFF set, and with what attributes?',
    query: 'BFF session cookie attributes Host prefix HttpOnly SameSite',
    answerContains: '__Host-ironauth_bff',
    expectedSource: 'docs/bff.md',
  },
  {
    step: 'How does the app defend against CSRF?',
    query: 'CSRF custom header state changing endpoints',
    answerContains: 'X-IronAuth-BFF',
    expectedSource: 'docs/bff.md',
  },
  {
    step: 'What happens when a refresh fails?',
    query: 'refresh failure session expired typed result',
    answerContains: 'destroys the session',
    expectedSource: 'docs/bff.md',
  },
  {
    step: 'Can I verify tokens on CloudFront Functions?',
    query: 'CloudFront Functions verify token supported',
    answerContains: 'not supported',
    expectedSource: 'docs/edge-verification.md',
  },
  {
    step: 'Which runtimes can verify an IronAuth token at the edge?',
    query: 'edge runtime support table Workers Deno Bun',
    answerContains: 'Cloudflare Workers',
    expectedSource: 'docs/edge-verification.md',
  },
  {
    step: 'How do I get an environment to develop against?',
    query: 'local dev emulator offline deterministic seed',
    answerContains: 'emulator',
    expectedSource: 'docs/EMULATOR.md',
  },
];

test('the corpus parses into retrievable sections', () => {
  // A parser that produced nothing would make every assertion below vacuous, and a search over
  // zero sections returns zero hits -- which reads as "no answer" rather than "no corpus".
  assert.ok(server.sectionCount > 100, `only ${server.sectionCount} sections parsed`);
  assert.ok(server.documents().length >= 15, server.documents().join(', '));
  assert.ok(server.documents().includes('docs/bff.md'));
});

test('the docs server exposes exactly two read-only tools', () => {
  assert.equal(DOCS_TOOLS.length, 2);
  const names = DOCS_TOOLS.map((tool) => tool.name).sort();
  assert.deepEqual(names, ['read_doc', 'search_docs']);
  // Every description tells an agent WHEN to reach for it. A tool description an agent cannot
  // act on is a tool it will not use at the moment it should.
  for (const tool of DOCS_TOOLS) {
    assert.ok(tool.description.length > 40, tool.name);
  }
});

for (const step of INTEGRATION_TASK) {
  test(`integration task: ${step.step}`, () => {
    const hits = server.search(step.query);
    assert.ok(hits.length > 0, `no hit for "${step.query}"`);
    const answering = hits.find((hit) => hit.excerpt.includes(step.answerContains));
    assert.ok(
      answering,
      `the guidance for "${step.step}" was not retrieved.\n` +
        `  looked for: ${step.answerContains}\n` +
        `  got: ${hits.map((hit) => `${hit.source} :: ${hit.heading}`).join(', ')}`,
    );
    // FROM THE RIGHT DOCUMENT. A phrase found in the wrong page is a coincidence that would
    // stop holding the moment either page changed.
    assert.equal(answering.source, step.expectedSource, step.step);
  });
}

test('every step of the recorded task is answered from the published docs alone', () => {
  // The criterion is "using ONLY the docs MCP server and skills". This asserts the conjunction:
  // not that some steps are answerable, but that no step of the task depends on knowledge the
  // corpus does not carry.
  const unanswered = INTEGRATION_TASK.filter((step) => {
    const hits = server.search(step.query);
    return !hits.some((hit) => hit.excerpt.includes(step.answerContains));
  });
  assert.deepEqual(
    unanswered.map((step) => step.step),
    [],
    'these steps cannot be completed from the documentation alone',
  );
  assert.ok(INTEGRATION_TASK.length >= 8, 'the task must be decomposed, not a single question');
});

test('read_doc returns a whole document, and nothing for one that is not published', () => {
  const page = server.read('docs/bff.md');
  assert.ok(page, 'docs/bff.md is published');
  assert.ok(page.includes('Backend-for-frontend'));
  // An INTERNAL decision record is not reachable, because the corpus this server reads excludes
  // them -- so the exclusion an agent should never see through holds here too.
  assert.equal(server.read('docs/design/TENANCY.md'), undefined);
  assert.equal(server.read('docs/nope.md'), undefined);
});

test('the skills an agent follows are checked in and say to search first', () => {
  // The criterion pairs the server with skills. A skill that does not tell an agent to search is
  // a skill that lets it answer from recall, which is the failure this whole feature addresses.
  for (const name of ['integrate-ironauth', 'migrate-to-ironauth']) {
    const skill = readFileSync(
      new URL(`../../../docs/skills/${name}.md`, import.meta.url),
      'utf8',
    );
    assert.ok(skill.includes('search_docs'), `${name} does not tell the agent to search`);
    assert.ok(skill.length > 1000, `${name} is too thin to follow`);
  }
});
