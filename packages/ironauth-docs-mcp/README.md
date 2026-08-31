# @ironauth/docs-mcp

Search and retrieval over the published IronAuth documentation, so a coding agent pulls current
guidance instead of recalling it.

## Two tools, both read-only

- `search_docs(query)` -- the matching sections, with their source paths.
- `read_doc(path)` -- one document in full.

There is no tool that writes anything and no credential anywhere in this package. It serves a
file. That is worth saying because `@ironauth/mcp` beside it is the opposite -- it drives
mutations with a scoped key -- and an operator wiring both into an agent should be able to tell
which is which at a glance.

## It reads the generated corpus, not `docs/`

The corpus is `docs/llms-full.txt`, which `scripts/gen-llms-txt.py` writes and
`scripts/llms-txt.sh` gates for freshness **and** coverage. So:

- the published set has one definition, and a document excluded from the agent-facing corpus (an
  internal decision record) cannot reach an agent through this server either;
- this server inherits the coverage guarantee rather than needing its own.

A server that walked `docs/` would be a second answer to "what is published", and the first time
the two disagreed one of them would be serving an agent something nobody meant to.

## Ranking

Term frequency over headings and body, with headings weighted, a cap on repeats, and a bonus for
covering every term. No embeddings.

The honest version of the tradeoff: this finds a section whose **words** match the question and
will miss one that answers it in different words. What it buys is being exactly as current as the
corpus, which a freshness gate already keeps matching the documentation set. An embedding index
is a second artifact to regenerate, and forgetting is silent and looks like a good answer.

## The eval

`src/eval.test.ts` is the recorded integration-task eval for issue #123 criterion 1. **It does
not run a model**, and it says so: what it measures is whether the server surfaces the guidance
each step of the task needs, and that the guidance retrieved is the *current* answer rather than
a plausible passage.

That is deliberate. An eval that ran a model would measure the model on the day it ran; this
measures the corpus and the retrieval, which are what change underneath.
