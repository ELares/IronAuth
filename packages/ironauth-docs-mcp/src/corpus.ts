// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The published documentation, as sections an agent can retrieve (issue #123).
 *
 * The corpus is `docs/llms-full.txt`, which `scripts/gen-llms-txt.py` writes from the published
 * set and `scripts/llms-txt.sh` gates for freshness AND coverage. This server reads that file
 * rather than walking `docs/` itself, and the reason is not convenience:
 *
 * - the published set has ONE definition, so a document excluded from the agent-facing corpus
 *   (an internal decision record) cannot reach an agent through this server either; and
 * - the coverage gate already proves the corpus matches the documentation set, so this server
 *   inherits that guarantee instead of needing its own.
 *
 * A server that walked `docs/` would be a second answer to "what is published", and the first
 * time the two disagreed one of them would be serving an agent something nobody meant to.
 */

/** One retrievable piece of documentation: a heading and the prose under it. */
export interface Section {
  /** The document this came from, as its repository path. */
  readonly source: string;
  /** The document's title. */
  readonly document: string;
  /** The heading this section sits under, or the document title for the opening prose. */
  readonly heading: string;
  /** The section's text. */
  readonly text: string;
}

/**
 * Split the generated corpus into sections.
 *
 * SECTIONS AND NOT DOCUMENTS, because retrieval granularity is the whole difference between a
 * useful docs server and a slow one. `docs/CONFIG.md` is thousands of lines; handing an agent
 * the whole file to answer "what is the session cookie called" spends its context on everything
 * else, and an agent that runs out of context guesses.
 */
export function parseCorpus(corpus: string): Section[] {
  const sections: Section[] = [];
  // The generator writes `---` then `# Title` then `Source: path` per document.
  const documents = corpus.split(/\n---\n/).slice(1);
  for (const block of documents) {
    const title = /^\s*#\s+(.+)$/m.exec(block)?.[1]?.trim() ?? '';
    const source = /^Source:\s+(.+)$/m.exec(block)?.[1]?.trim() ?? '';
    if (!source) {
      continue;
    }
    const body = block.slice(block.indexOf(`Source: ${source}`) + `Source: ${source}`.length);
    let heading = title;
    let buffer: string[] = [];
    const flush = () => {
      const text = buffer.join('\n').trim();
      if (text.length > 0) {
        sections.push({ source, document: title, heading, text });
      }
      buffer = [];
    };
    let inFence = false;
    for (const line of body.split('\n')) {
      // A `#` inside a fenced block is a comment in someone's shell example, not a heading.
      // Splitting on it would cut a code sample in half and hand an agent the second half.
      if (line.trimStart().startsWith('```')) {
        inFence = !inFence;
      }
      if (!inFence && /^#{2,6}\s+/.test(line)) {
        flush();
        heading = line.replace(/^#{2,6}\s+/, '').trim();
        continue;
      }
      buffer.push(line);
    }
    flush();
  }
  return sections;
}
