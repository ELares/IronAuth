// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cost-bounded CEL evaluation (issue #113, acceptance criterion 2).
//!
//! > CEL expressions execute under a cost budget; an expression exceeding it aborts
//! > DETERMINISTICALLY with a typed error and the configured failure policy applies.
//!
//! The word `deterministically` is what shapes this whole module. It rules out a wall-clock
//! timeout: two runs of the same expression on the same input must reach the same verdict, and
//! a timeout makes the verdict a function of machine load. So the budget is decided BEFORE
//! evaluation, from the expression and the declared shape of its input, and the same pair
//! always reaches the same answer.
//!
//! # Why the two obvious designs do not work, measured
//!
//! The `cel` crate has no cost accounting: no fuel, no step counter, nothing. What it has is a
//! PARSE-time `max_recursion_depth` (default 96), which bounds how deeply an expression NESTS
//! and says nothing about how much work it does.
//!
//! **A static AST bound does not work.** Cost is not a function of the expression alone:
//!
//! ```text
//! groups.filter(g, g.startsWith('g1')).size()   <- 5 AST nodes
//! over a 200,000-element list                   -> 423 SECONDS
//! ```
//!
//! **An input bound alone does not work either.** Cost is not a function of the input alone:
//!
//! ```text
//! depth 1, n = 10,000    ->   0.32 s      a single filter, the most ordinary expression there is
//! depth 2, n = 10,000    ->  12.8  s
//! depth 3, n =  1,000    -> 104    s
//! ```
//!
//! Measured, the shape is `n^depth`: macros nest, and each nesting level multiplies the work by
//! the cardinality again. Which is the model this module implements.
//!
//! # The rule
//!
//! Refuse before evaluating when `n^depth` exceeds the budget, where `depth` is macro nesting
//! read off the expression and `n` is the largest DECLARED cardinality of the input
//! collections. Both are known without running anything, so the verdict is a pure function of
//! (expression, declared shape, budget).
//!
//! # What it costs, said plainly
//!
//! It refuses some expressions that would in fact have been cheap, because `n` is the declared
//! maximum rather than the actual size at evaluation time. A tenant whose users each have three
//! groups is still budgeted at whatever the document declares. That is the price of deciding
//! before evaluating, and deciding before evaluating is exactly what `deterministically` buys.
//!
//! A future version could replace the estimate with real cost accounting in the evaluator (a
//! fork, or an upstream change to cel-rust). That would bound ACTUAL work rather than declared
//! worst case and would admit more expressions. It is a strictly better answer and a much
//! larger change; this one lands entirely inside IronAuth and does not foreclose it, because
//! callers see a verdict rather than the model behind it.
//!
//! # What this crate does NOT yet do
//!
//! It does not ENFORCE anything, because nothing calls it. [`compile_within_budget`] is the
//! only gate, and it hands back a `cel::Program` a caller can also obtain by calling
//! `cel::Program::compile` directly -- so the budget is a door beside an open wall until the
//! hook that evaluates these expressions exists and is made to go through it.
//!
//! Said plainly rather than left implied: this crate is criterion 2's MODEL, measured and
//! bounded, and criterion 2 is not closed until a caller cannot avoid it. The shape that closes
//! it is for this crate to own evaluation end to end -- wrapping `Context` and exposing an
//! `evaluate` that takes the shape -- so a caller never needs `cel` in its own manifest, plus a
//! `disallowed-methods` lint on `cel::Program::compile` outside this crate. That belongs with
//! the hook, which is where the first caller will be.

use cel::common::ast::{EntryExpr, Expr, IdedEntryExpr};

/// The largest `n^(depth + 1)` an expression may cost before it is refused.
///
/// Calibrated against every timing in the module header, and it is the TIGHTEST value that
/// reproduces them: each measured case under ~350 ms is admitted and each one above it is
/// refused, with no exceptions in either direction.
///
/// ```text
/// admitted   depth 1 n=1,000     10^6    measured   4.9 ms
/// admitted   depth 1 n=10,000    10^8    measured 320   ms
/// admitted   depth 2 n=1,000     10^9    measured 124   ms
/// admitted   depth 3 n=100       10^8    measured 104   ms
/// refused    depth 1 n=200,000   4x10^10 measured 423   s
/// refused    depth 2 n=10,000    10^12   measured  12.8 s
/// refused    depth 3 n=1,000     10^12   measured 104   s
/// ```
///
/// It moved from `10^6` when the exponent was corrected from `depth` to `depth + 1`: the same
/// split needs a larger number once each level counts its accumulation. A budget rather than a
/// limit on either term separately, because neither term alone predicts the cost.
pub const DEFAULT_COST_BUDGET: u64 = 1_000_000_000;

/// Why an expression was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostError {
    /// The expression did not parse or compile.
    ///
    /// Carries the compiler's message. CEL's own recursion limit surfaces here, which is a
    /// second, independent bound: an expression too deeply nested to parse never reaches the
    /// cost estimate at all.
    Uncompilable(String),
    /// The expression's estimated cost exceeds the budget.
    ///
    /// Both numbers travel so an operator can see WHY rather than only that it was refused: an
    /// expression refused at 10^8 against a budget of 10^6 needs a different fix from one
    /// refused at 1.1 million.
    OverBudget {
        /// The estimate, `n^depth`, saturating at [`u64::MAX`].
        estimated: u64,
        /// The budget it exceeded.
        budget: u64,
    },
}

impl core::fmt::Display for CostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Uncompilable(message) => write!(f, "expression does not compile: {message}"),
            Self::OverBudget { estimated, budget } => write!(
                f,
                "expression may cost up to {estimated} operations against a budget of {budget}"
            ),
        }
    }
}

impl std::error::Error for CostError {}

/// The declared shape of the input an expression will be evaluated against.
///
/// The `max_collection_size` is a DECLARATION, not a measurement: it is what the typed input
/// document promises, and the estimate is only as honest as it is. A document that declares a
/// bound it does not enforce turns this budget into decoration, so the enforcement belongs with
/// whatever builds the document rather than here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputShape {
    /// The largest number of elements any collection in the input may hold.
    pub max_collection_size: u64,
}

/// How deeply comprehensions nest in `expression`, and therefore how many times the input
/// cardinality multiplies into the cost.
///
/// Walks the PARSED TREE. Every macro in CEL expands to an `Expr::Comprehension`, so the
/// question "is this a macro" is answered by the same parser that decides what a macro IS,
/// rather than by a second opinion about bytes.
///
/// # Why this is not a text scan any more
///
/// It was one, and the scan had three holes, all of them the UNSAFE direction and all of them
/// found by driving the real evaluator:
///
/// * `existsOne` is a registered alias for `exists_one` -- it is the CEL-spec spelling, and
///   the one cel-rust's own parser tests use -- and it was not in the hand-copied list of five
///   names. Any nesting of it reported depth 0 and was admitted at ANY declared cardinality
///   against ANY budget. Measured: three nested `existsOne` over 400 elements ran 12.5 seconds
///   and was estimated at 1.
/// * a `)` inside a STRING LITERAL popped a real macro's paren frame, halving the counted
///   depth. Six characters turned this module's own pinned twelve-second case into an admitted
///   one.
/// * CEL has `//` comments, and a `)` inside one did the same thing.
///
/// The old comment justified the scan by asserting that cel's parsed expression "is not a
/// public tree this crate can traverse". That was FALSE -- `cel::common::ast` is a public
/// module, `IdedExpr` is re-exported, and `Program::expression()` is public -- and it was the
/// premise the whole design rested on. Strings and comments are not questions the tree can
/// even ask: the lexer that owns their definition discarded them before this sees anything.
fn comprehension_depth(expression: &Expr) -> u32 {
    match expression {
        // The one node that iterates. Its own depth is one more than the deepest of its parts,
        // and the parts are walked too because a macro's BODY is where nesting lives.
        Expr::Comprehension(comprehension) => {
            1 + [
                &comprehension.iter_range,
                &comprehension.accu_init,
                &comprehension.loop_cond,
                &comprehension.loop_step,
                &comprehension.result,
            ]
            .into_iter()
            .map(|part| comprehension_depth(&part.expr))
            .max()
            .unwrap_or(0)
        }
        // EVERY branch that can contain a sub-expression is walked. A `_ => 0` arm here is the
        // same defect one level up: review's first draft of this walk used one and under-counted
        // a comprehension inside a map literal, which is the exact failure mode the whole
        // function exists to prevent.
        Expr::Call(call) => call
            .target
            .iter()
            .map(|target| comprehension_depth(&target.expr))
            .chain(call.args.iter().map(|arg| comprehension_depth(&arg.expr)))
            .max()
            .unwrap_or(0),
        Expr::Select(select) => comprehension_depth(&select.operand.expr),
        Expr::List(list) => list
            .elements
            .iter()
            .map(|element| comprehension_depth(&element.expr))
            .max()
            .unwrap_or(0),
        Expr::Map(map) => entries_depth(&map.entries),
        Expr::Struct(structure) => entries_depth(&structure.entries),
        // Leaves: an identifier, a literal, or an unset node contains nothing that iterates.
        Expr::Ident(_) | Expr::Literal(_) | Expr::Unspecified => 0,
    }
}

/// The deepest comprehension in a map or struct literal's entries.
///
/// BOTH arms, because a comprehension can sit in a map key as easily as in its value.
fn entries_depth(entries: &[IdedEntryExpr]) -> u32 {
    entries
        .iter()
        .map(|entry| match &entry.expr {
            EntryExpr::StructField(field) => comprehension_depth(&field.value.expr),
            EntryExpr::MapEntry(entry) => {
                comprehension_depth(&entry.key.expr).max(comprehension_depth(&entry.value.expr))
            }
        })
        .max()
        .unwrap_or(0)
}

/// The estimated worst-case cost of a parsed expression against `shape`: `n^(depth + 1)`.
///
/// # Why `depth + 1` and not `depth`
///
/// Because a comprehension does not merely visit `n` elements, it ACCUMULATES: cel expands
/// `filter` and `map` to `@result + [x]`, a list append per accepted element, which makes even
/// a single filter quadratic in the collection rather than linear.
///
/// That is not a refinement, it is a correction. Under `n^depth` this module's own headline
/// example -- one filter over 200,000 elements, MEASURED at 423 seconds -- estimated 200,000
/// against a budget of 1,000,000 and was ADMITTED. The model contradicted the measurement it
/// was introduced with.
///
/// Saturating, so a deeply nested expression over a large declared collection reports
/// [`u64::MAX`] rather than wrapping to a small number and being admitted. An estimate that
/// overflowed into "cheap" would be the worst possible failure of this function.
#[must_use]
pub fn estimate_parsed_cost(expression: &Expr, shape: InputShape) -> u64 {
    let depth = comprehension_depth(expression);
    if depth == 0 {
        // Nothing iterates, so the cost does not scale with the input at all.
        return 1;
    }
    shape
        .max_collection_size
        .checked_pow(depth.saturating_add(1))
        .unwrap_or(u64::MAX)
}

/// Compile `expression`, refusing it when its estimated cost exceeds `budget`.
///
/// The refusal happens BEFORE any evaluation, which is what makes it deterministic: the same
/// expression against the same declared shape always reaches the same verdict, on any machine,
/// under any load.
///
/// # Errors
///
/// [`CostError::Uncompilable`] when the expression does not compile, and
/// [`CostError::OverBudget`] when its estimate exceeds `budget`.
pub fn compile_within_budget(
    expression: &str,
    shape: InputShape,
    budget: u64,
) -> Result<cel::Program, CostError> {
    // COMPILE FIRST, and estimate from the SAME program. A malformed expression is a different
    // fault from an expensive one, and an operator who gets "over budget" for a typo is sent to
    // the wrong place. It is also where CEL's own recursion limit fires, and -- since the
    // estimate now walks the parsed tree -- it is the only thing that produces a tree to walk.
    let program = cel::Program::compile(expression)
        .map_err(|error| CostError::Uncompilable(error.to_string()))?;
    let estimated = estimate_parsed_cost(&program.expression().expr, shape);
    if estimated > budget {
        return Err(CostError::OverBudget { estimated, budget });
    }
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::{
        CostError, DEFAULT_COST_BUDGET, InputShape, compile_within_budget, comprehension_depth,
        estimate_parsed_cost,
    };

    fn shape(n: u64) -> InputShape {
        InputShape {
            max_collection_size: n,
        }
    }

    /// The depth of an expression, via the same parser the evaluator uses.
    fn depth(expression: &str) -> u32 {
        let program = cel::Program::compile(expression).expect("compiles");
        comprehension_depth(&program.expression().expr)
    }

    /// Depth counts comprehensions, and only comprehensions.
    #[test]
    fn depth_counts_comprehension_nesting() {
        assert_eq!(depth("user.email"), 0);
        assert_eq!(depth("size(groups) > 3"), 0);
        assert_eq!(depth("groups.filter(g, g == 'a')"), 1);
        assert_eq!(depth("groups.all(g, g != '')"), 1);
        // Two macros in SEQUENCE are depth one: neither runs inside the other.
        assert_eq!(
            depth("groups.filter(g, g == 'a') == roles.filter(r, r == 'b')"),
            1
        );
        // NESTED is what multiplies.
        assert_eq!(depth("groups.filter(a, groups.exists(b, b == a))"), 2);
        assert_eq!(
            depth("groups.filter(a, groups.exists(b, groups.exists(c, c == a)))"),
            3
        );
        // A name that merely resembles a macro is a plain call.
        assert_eq!(depth("user.myfilter(x)"), 0);
    }

    /// THE THREE BYPASSES THE TEXT SCAN HAD. Each was measured against the real evaluator, and
    /// each reported depth 0 -- estimate 1, admitted at any cardinality against any budget.
    #[test]
    fn the_spellings_that_defeated_the_text_scan_are_counted() {
        // 1. `existsOne`, the CEL-spec spelling and the one cel-rust's own parser tests use,
        //    was missing from a hand-copied list of five names.
        assert_eq!(depth("groups.existsOne(g, g == 'a')"), 1);
        assert_eq!(
            depth("groups.existsOne(a, groups.existsOne(b, groups.existsOne(c, c == a)))"),
            3,
            "three nested existsOne over 400 elements measured 12.5 SECONDS and was estimated \
             at 1"
        );
        // 2. A `)` inside a STRING popped a real macro's paren frame and halved the depth. Six
        //    characters turned this module's own pinned 12.8-second case into an admitted one.
        assert_eq!(
            depth("groups.filter(a, ')' == '' || groups.exists(b, b == a)).size()"),
            2
        );
        // 3. CEL has `//` comments, and a `)` inside one did the same.
        assert_eq!(
            depth("groups.filter(a, // )\n groups.exists(b, b == a)).size()"),
            2
        );
        // And the safe-direction imprecision the scan had is GONE rather than merely tolerated:
        // a macro name inside a string is not a macro, and the tree knows it.
        assert_eq!(depth("user.note == 'filter('"), 0);
    }

    /// A comprehension inside a map or list literal is still a comprehension.
    ///
    /// Review's first draft of this walk used a `_ => 0` arm and under-counted exactly this,
    /// which is the same defect one level up from the scan it replaced.
    #[test]
    fn a_comprehension_nested_in_a_literal_is_not_lost() {
        assert_eq!(depth("{'k': groups.filter(g, g == 'a')}['k']"), 1);
        assert_eq!(depth("[groups.filter(g, g == 'a')][0]"), 1);
        // In a map KEY, not only a value.
        assert_eq!(depth("{groups.filter(g, g == 'a')[0]: 1}"), 1);
    }

    /// The estimate is `n^(depth + 1)`, and it SATURATES rather than wrapping.
    #[test]
    fn the_estimate_saturates_instead_of_wrapping_to_cheap() {
        let parsed = |expression: &str| cel::Program::compile(expression).expect("compiles");
        assert_eq!(
            estimate_parsed_cost(&parsed("user.email").expression().expr, shape(10_000)),
            1
        );
        assert_eq!(
            estimate_parsed_cost(
                &parsed("groups.filter(g, g == 'a')").expression().expr,
                shape(1_000)
            ),
            1_000_000,
            "one filter is quadratic: cel expands it to `@result + [x]`, an append per element"
        );
        let absurd = "groups.filter(a, groups.filter(b, groups.filter(c, groups.filter(d, \
                      groups.filter(e, groups.filter(f, groups.filter(g, groups.filter(h, \
                      groups.filter(i, groups.filter(j, j == a))))))))))";
        assert_eq!(
            estimate_parsed_cost(&parsed(absurd).expression().expr, shape(1_000_000)),
            u64::MAX,
            "an estimate that overflowed would report `cheap` for the most expensive thing \
             anyone could write"
        );
    }

    /// The MEASURED table, as a table of verdicts.
    ///
    /// Under the old `n^depth` model the first refused row -- this module's own headline
    /// example, 423 seconds -- was ADMITTED. The model contradicted the measurement it was
    /// introduced with, which is what makes pinning these rows worth the lines.
    #[test]
    fn the_budget_admits_what_was_measured_fast_and_refuses_what_was_measured_slow() {
        let one = "groups.filter(g, g.startsWith('g1')).size()";
        let two = "groups.filter(a, groups.exists(b, b == a)).size()";
        let three = "groups.filter(a, groups.exists(b, groups.exists(c, c == a)))";

        for (expression, n, measured) in [
            (one, 1_000_u64, "4.9 ms"),
            (one, 10_000, "320 ms"),
            (two, 1_000, "124 ms"),
            (three, 100, "104 ms"),
        ] {
            assert!(
                compile_within_budget(expression, shape(n), DEFAULT_COST_BUDGET).is_ok(),
                "n={n} measured at {measured} and must be admitted"
            );
        }
        for (expression, n, measured) in [
            (one, 200_000_u64, "423 s"),
            (two, 10_000, "12.8 s"),
            (three, 1_000, "104 s"),
        ] {
            assert!(
                matches!(
                    compile_within_budget(expression, shape(n), DEFAULT_COST_BUDGET),
                    Err(CostError::OverBudget { .. })
                ),
                "n={n} measured at {measured} and must be refused"
            );
        }
    }

    /// A malformed expression is UNCOMPILABLE, not over budget.
    #[test]
    fn a_malformed_expression_is_a_different_fault_from_an_expensive_one() {
        let outcome = compile_within_budget("groups.filter(", shape(10), DEFAULT_COST_BUDGET);
        assert!(
            matches!(outcome, Err(CostError::Uncompilable(_))),
            "{outcome:?}"
        );
        // And it is reported as such even when it would ALSO be over budget.
        let outcome = compile_within_budget("groups.filter(", shape(u64::MAX), 1);
        assert!(
            matches!(outcome, Err(CostError::Uncompilable(_))),
            "{outcome:?}"
        );
    }

    /// The verdict is a pure function of (expression, shape, budget).
    ///
    /// Criterion 2's actual demand. A wall-clock timeout would fail this on a loaded machine,
    /// which is the whole reason it is not one.
    #[test]
    fn the_same_expression_and_shape_always_reach_the_same_verdict() {
        let expression = "groups.filter(a, groups.exists(b, b == a))";
        let first = compile_within_budget(expression, shape(10_000), DEFAULT_COST_BUDGET);
        for _ in 0..50 {
            let again = compile_within_budget(expression, shape(10_000), DEFAULT_COST_BUDGET);
            assert_eq!(
                format!("{:?}", again.as_ref().err()),
                format!("{:?}", first.as_ref().err()),
                "the verdict must not depend on anything but its inputs"
            );
        }
    }

    /// The refusal names both numbers, so an operator can tell which fix applies.
    #[test]
    fn the_refusal_carries_the_estimate_and_the_budget() {
        let Err(CostError::OverBudget { estimated, budget }) = compile_within_budget(
            "groups.filter(a, groups.exists(b, b == a))",
            shape(10_000),
            DEFAULT_COST_BUDGET,
        ) else {
            panic!("must be refused");
        };
        assert_eq!(estimated, 1_000_000_000_000);
        assert_eq!(budget, DEFAULT_COST_BUDGET);
        assert!(
            CostError::OverBudget { estimated, budget }
                .to_string()
                .contains("1000000000000"),
            "the message must carry the estimate, not merely the fact of refusal"
        );
    }
}
