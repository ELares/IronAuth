// SPDX-License-Identifier: MIT OR Apache-2.0
//! A CUSTOM FACTOR, implemented entirely as a component (issue #114 criterion 6).
//!
//! The sample the criterion asks for: a working custom factor that the host has no knowledge of
//! and that required no change to the flow engine to add.
//!
//! ## The factor
//!
//! A shared-wordmark challenge. The tenant configures a secret list of words; a login is asked
//! to name the word at a position the challenge picks, twice, and both rounds must pass. It is
//! deliberately mundane -- what it demonstrates is not cryptography but that the HOST NEVER
//! LEARNS WHAT THE CHALLENGE IS. The host renders a prompt and some fields it cannot interpret,
//! holds an opaque string, and asks this component whether the answer was right.
//!
//! ## Where each piece of state lives, and why
//!
//! The expected answer travels in `private-params`, which the host holds for the life of the
//! round and never renders. The POSITION travels in `public-params`, because the user has to be
//! able to see which word is being asked for. Putting the expected word in `public-params`
//! would publish the answer with the question, and putting the position in `private-params`
//! would make the challenge unanswerable.
//!
//! Nothing is kept in a global. The three calls are three separate instantiations with three
//! separate stores, so a global would be empty on the next call anyway -- and that is the right
//! shape rather than a limitation, because two concurrent logins in one process must not be
//! able to see each other's challenge.
//!
//! ## Two rounds
//!
//! `define` returns `challenge` while fewer than two rounds have completed and `succeed` after,
//! and it FAILS THE FACTOR on a wrong answer rather than allowing a retry. That combination is
//! what makes the sample exercise all three decision arms: a test can drive it to `succeed`, to
//! `fail`, and through more than one `challenge`.

wit_bindgen::generate!({ path: "../../wit", world: "custom-challenge-hook" });

use exports::ironauth::hooks::custom_challenge::{
    Answer, ChallengeSpec, Context, Decision, Field, Guest,
};
use ironauth::hooks::secrets;

struct Factor;

/// The secret this factor reads: the tenant's wordmark list, comma separated.
///
/// A GRANTED SECRET, not a constant: the whole point of a custom factor is that its policy is
/// the tenant's. A component with no grant for this name is told `none` by the host and declines,
/// which is the deny-by-default path and is worth having a sample exercise.
const WORDMARK_SECRET: &str = "wordmark_list";

/// How many rounds must pass before the factor is satisfied.
const ROUNDS: u32 = 2;

/// The word this round asks for, chosen from the list by the round number.
///
/// DETERMINISTIC, from the round rather than from a random source. The sandbox denies ambient
/// randomness by construction (`random-escape` is a fixture that proves it), so a component that
/// wanted an unpredictable position would have to be granted `fetch` and get it from somewhere.
/// A sample should not pretend otherwise: this picks by round, and the doc says so.
fn word_for(list: &[&str], round: u32) -> Option<String> {
    let index = usize::try_from(round).ok()?;
    list.get(index % list.len().max(1)).map(|w| (*w).to_owned())
}

fn wordmarks() -> Result<Vec<String>, String> {
    let raw = secrets::get(WORDMARK_SECRET)
        .ok_or_else(|| format!("this factor was not granted the `{WORDMARK_SECRET}` secret"))?;
    let words: Vec<String> = raw
        .split(',')
        .map(|w| w.trim().to_owned())
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return Err("the wordmark list is empty".to_owned());
    }
    Ok(words)
}

/// Escape a string into a JSON string literal.
///
/// Hand-written rather than a serde dependency: a fixture that pulled in a JSON stack would
/// measure the stack's code size in the cold-start benchmark. The two characters that must be
/// escaped for the values this component emits are the backslash and the quote.
fn json_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Read one string field out of a flat JSON object, without a JSON parser.
///
/// The only shapes this has to read are the ones `create` above wrote, so it looks for
/// `"key":"value"` and takes the value. A component reading UNTRUSTED JSON would need a real
/// parser; this reads its own output, which the host round-tripped unchanged.
fn json_field(source: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = source.find(&needle)? + needle.len();
    let rest = &source[start..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => out.push(chars.next()?),
            other => out.push(other),
        }
    }
    None
}

impl Guest for Factor {
    /// Decide what happens next.
    ///
    /// A WRONG ANSWER ENDS THE FACTOR. This is the strict choice of the two available, and it is
    /// the one a sample should make: a component that allowed unlimited retries would turn a
    /// two-word list into something a caller can enumerate.
    fn define(ctx: Context) -> Result<Decision, String> {
        if ctx.previous_passed == Some(false) {
            return Ok(Decision::Fail(
                "the wordmark answer was wrong".to_owned(),
            ));
        }
        if ctx.round >= ROUNDS {
            return Ok(Decision::Succeed);
        }
        Ok(Decision::Challenge)
    }

    /// Build this round's challenge.
    fn create(ctx: Context) -> Result<ChallengeSpec, String> {
        let words = wordmarks()?;
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let expected = word_for(&refs, ctx.round)
            .ok_or_else(|| "no wordmark available for this round".to_owned())?;
        let position = usize::try_from(ctx.round).unwrap_or(0) % words.len().max(1);
        Ok(ChallengeSpec {
            prompt: "wordmark.prompt".to_owned(),
            fields: vec![Field {
                name: "wordmark".to_owned(),
                label: "wordmark.label".to_owned(),
                // MASKED. The answer is a shared secret between the tenant and the user, so it
                // is exactly the kind of value that must not sit in a screenshot or a log.
                secret: true,
            }],
            // The expected word, which the host holds and never renders.
            private_params: format!("{{\"expected\":{}}}", json_string(&expected)),
            // The POSITION, which the user needs in order to answer at all.
            public_params: format!("{{\"position\":\"{position}\"}}"),
        })
    }

    /// Check the answer against what `create` put aside.
    fn verify(
        _ctx: Context,
        private_params: String,
        answers: Vec<Answer>,
    ) -> Result<bool, String> {
        let expected = json_field(&private_params, "expected")
            .ok_or_else(|| "the challenge parameters carried no expected answer".to_owned())?;
        let given = answers
            .iter()
            .find(|answer| answer.name == "wordmark")
            .map(|answer| answer.value.trim().to_owned())
            .ok_or_else(|| "the submission carried no `wordmark` answer".to_owned())?;
        // CASE-INSENSITIVE, because the user is typing a word they were told out of band and a
        // factor that failed on capitalization would be a support burden rather than a control.
        Ok(given.eq_ignore_ascii_case(&expected))
    }
}

export!(Factor);
