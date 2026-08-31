# Human-timed quickstart runs

DX evidence for issue #116 criterion 3. **Not a gate** -- see `docs/RELEASING.md` for why.

CI already proves the guides work: `scripts/quickstart.sh` runs each guide's documented commands
verbatim on every push, under a 15-minute budget. What it cannot tell us is what a guide feels
like, because a machine does not mistype a command, re-read a paragraph, or stop to work out
which of two things it was meant to install.

## How to record one

Walk one quickstart start to finish on a machine that has never run it. Time from **opening the
guide** to **a successful login** -- not from the first command, because deciding what to do is
part of the experience being measured.

Then add a row, and write the notes even when the time was good. **The time is the signal that
something is wrong; the notes are the only thing that says what.**

```
### <version> -- <guide>

- **Wall clock:** 6m40s (guide open -> `signed in as ...`)
- **Machine:** clean macOS 15, no Rust toolchain, no Go
- **Where the time went:** 4m of it was the first `cargo build`
- **Where I hesitated:** it was not obvious the emulator keeps running in the background
- **What I got wrong:** pasted step 3 before step 2 finished; the error was clear
- **Would a newcomer finish?** yes
```

## Runs

_No runs recorded yet. The template above is what one looks like; the first entry lands with the
first release that ships a quickstart._

This section being empty is a fact rather than an omission, and it is written down rather than
left blank: a heading with nothing under it reads as "nobody did this", which is exactly what it
means. It is not a gate, so it does not block; it does mean there is no human evidence yet.
