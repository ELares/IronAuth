// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The docs MCP server (issue #123).
 *
 * Two tools: `search_docs` and `read_doc`. A coding agent uses them to pull CURRENT integration
 * guidance rather than recalling a version of it from training, which is the whole point -- the
 * failure this addresses is an agent confidently writing an integration against an API shape
 * that was true eighteen months ago.
 *
 * ## Read-only, and structurally so
 *
 * There is no tool that writes anything, and there is no credential anywhere in this package. It
 * serves a file. That is worth stating because the admin MCP server beside it is the opposite --
 * it drives mutations with a scoped key -- and an operator wiring both into an agent should be
 * able to tell at a glance which is which.
 *
 * ## Why the ranking is deliberately simple
 *
 * Term frequency over headings and body, with headings weighted. No embeddings, no index to
 * build, no model to keep in step with the docs.
 *
 * That is a real tradeoff and the honest version of it is: this finds a section whose words
 * match the question, and it will miss a section that answers the question in different words.
 * What it buys is that it is exactly as current as `docs/llms-full.txt`, which a freshness gate
 * already keeps matching the documentation set -- so the answer an agent gets is never staler
 * than the last commit. An embedding index is a second artifact to regenerate, and the failure
 * mode of forgetting is silent and looks like a good answer.
 */

import { type Section, parseCorpus } from './corpus.js';

/** A search hit. */
export interface Hit {
  readonly source: string;
  readonly document: string;
  readonly heading: string;
  /** The matching text, truncated for an agent's context. */
  readonly excerpt: string;
  /** Higher is a better match. Comparable within one result set only. */
  readonly score: number;
}

/** The tools this server exposes. Read-only, both of them. */
export const DOCS_TOOLS = [
  {
    name: 'search_docs',
    description:
      'Search the IronAuth documentation. Returns the matching sections with their source paths. ' +
      'Use this before writing any IronAuth integration code, so the guidance is current rather ' +
      'than recalled.',
    required: ['query'],
  },
  {
    name: 'read_doc',
    description:
      'Read one IronAuth document in full by its repository path, e.g. docs/bff.md. Use after ' +
      'search_docs when a section is not enough.',
    required: ['path'],
  },
] as const;

/** Words too common to discriminate. Dropped from the query, never from the text. */
const STOP = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'do', 'for', 'from', 'how', 'i', 'in', 'is',
  'it', 'my', 'of', 'on', 'or', 'the', 'to', 'use', 'what', 'when', 'where', 'with',
]);

function terms(query: string): string[] {
  return query
    .toLowerCase()
    .split(/[^a-z0-9_-]+/)
    .filter((word) => word.length > 1 && !STOP.has(word));
}

export class DocsMcpServer {
  readonly #sections: Section[];

  /** Build from the generated corpus (`docs/llms-full.txt`). */
  constructor(corpus: string) {
    this.#sections = parseCorpus(corpus);
  }

  /** How many sections were parsed. For tests and for a startup log. */
  get sectionCount(): number {
    return this.#sections.length;
  }

  /** Every document path in the corpus. */
  documents(): string[] {
    return [...new Set(this.#sections.map((section) => section.source))].sort();
  }

  /** Search, best first. */
  search(query: string, limit = 5): Hit[] {
    const wanted = terms(query);
    if (wanted.length === 0) {
      return [];
    }
    const scored = this.#sections.map((section) => {
      const heading = section.heading.toLowerCase();
      const text = section.text.toLowerCase();
      let score = 0;
      for (const term of wanted) {
        // A HEADING MATCH IS WORTH MORE than a body match, because a section whose heading names
        // the thing is usually the section about it, while a body mention is often a passing
        // reference from somewhere else. Weighted rather than filtered, so a body-only match is
        // still reachable when nothing names it.
        if (heading.includes(term)) {
          score += 8;
        }
        // Occurrences, capped. Uncapped, one section repeating a word forty times outranks the
        // section that defines it, which is how term frequency usually goes wrong.
        const occurrences = text.split(term).length - 1;
        score += Math.min(occurrences, 5);
      }
      // EVERY TERM PRESENT beats more occurrences of some of them: a query is a conjunction in
      // the asker's head even when it is a bag of words to the ranker.
      const covered = wanted.filter(
        (term) => heading.includes(term) || text.includes(term),
      ).length;
      if (covered === wanted.length && wanted.length > 1) {
        score += 20;
      }
      return { section, score };
    });
    return scored
      .filter((entry) => entry.score > 0)
      .sort((left, right) => right.score - left.score)
      .slice(0, limit)
      .map(({ section, score }) => {
        // THE HEADING IS PART OF THE EXCERPT, not just a field beside it. Much of this
        // documentation puts the answer in the heading -- "CloudFront Functions is not
        // supported", "Backend-for-frontend -- what to build" -- and an excerpt of the body
        // alone hands an agent the reasoning without the conclusion.
        //
        // Measured: two steps of the integration eval failed for exactly this, and both were
        // sections whose heading WAS the answer.
        const body =
          section.text.length > 1200 ? `${section.text.slice(0, 1200)}...` : section.text;
        return {
          source: section.source,
          document: section.document,
          heading: section.heading,
          excerpt: `## ${section.heading}\n\n${body}`,
          score,
        };
      });
  }

  /** Every section of one document, in order, or `undefined` when there is no such path. */
  read(path: string): string | undefined {
    const parts = this.#sections.filter((section) => section.source === path);
    if (parts.length === 0) {
      return undefined;
    }
    return parts
      .map((section) => (section.heading === section.document ? section.text : `## ${section.heading}\n\n${section.text}`))
      .join('\n\n');
  }
}
