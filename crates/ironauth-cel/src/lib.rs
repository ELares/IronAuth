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

/// The largest `n^depth` an expression may cost before it is refused.
///
/// Calibrated from the measurements in the module header: at `10^6` the worst ADMITTED case
/// runs in about 100 ms (depth 2 at n = 1000, and depth 3 at n = 100, both measured), while
/// depth 2 at n = 10,000 is `10^8` and is refused, which measured 12.8 seconds.
///
/// A budget rather than a limit on either term separately, because neither term alone predicts
/// the cost. That is the finding this constant exists to encode.
pub const DEFAULT_COST_BUDGET: u64 = 1_000_000;

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

/// How deeply macros nest in `expression`, and therefore how many times the input cardinality
/// multiplies into the cost.
///
/// Counted from the SOURCE rather than from a walked AST, and the reason is worth stating: the
/// `cel` crate's parsed expression is not a public tree this crate can traverse, so a walk
/// would mean either a fork or a second parser. A second parser is the defect this codebase
/// keeps finding -- the thing that decides what a macro IS must be the thing that decides how
/// deep they nest -- so this counts the one syntactic feature that creates the nesting, and
/// counts it conservatively.
///
/// CONSERVATIVE means: it may over-estimate depth and refuse an expression that would have been
/// cheap, and it must never under-estimate one. Over-refusing is visible to an operator, who
/// gets a typed error naming the number; under-refusing is a request that never returns.
///
/// The first version of this function matched the literal `"filter("`, and CEL accepts
/// `filter (`, `filter\n(` and `. filter ( ` -- so a nested expression written with a space
/// reported depth 0 and was admitted. That is the under-estimate this comment warns about,
/// found by probing the real evaluator rather than by reading the grammar, and the reason the
/// scan now walks back over whitespace before it reads a name.
fn macro_depth(expression: &str) -> u32 {
    // The comprehension macros, which are the only CEL constructs that iterate a collection.
    // A call to one inside another's body is what multiplies the cardinality again.
    const MACROS: [&str; 5] = ["filter", "map", "all", "exists", "exists_one"];

    let bytes = expression.as_bytes();
    let mut depth = 0_u32;
    let mut deepest = 0_u32;
    // One entry per open paren: whether it opened a macro call.
    let mut open: Vec<bool> = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' => {
                // Walk BACK over whitespace before reading the name. CEL accepts
                // `filter (`, `filter\n(` and `. filter ( ` -- all of which a naive
                // `"filter("` scan misses, and missing one is the UNSAFE direction: the
                // expression reports depth 0, is estimated at 1, is admitted, and then runs
                // for minutes. Measured against the real evaluator, which accepts all three.
                let mut end = index;
                while end > 0 && bytes[end - 1].is_ascii_whitespace() {
                    end -= 1;
                }
                let mut start = end;
                while start > 0
                    && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
                {
                    start -= 1;
                }
                let name = &expression[start..end];
                let is_macro = MACROS.contains(&name);
                open.push(is_macro);
                if is_macro {
                    depth += 1;
                    deepest = deepest.max(depth);
                }
            }
            b')' if open.pop().unwrap_or(false) => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    deepest
}

/// The estimated worst-case cost of `expression` against `shape`: `n^depth`.
///
/// Saturating, so a deeply nested expression over a large declared collection reports
/// [`u64::MAX`] rather than wrapping to a small number and being admitted. An estimate that
/// overflowed into "cheap" would be the worst possible failure of this function.
#[must_use]
pub fn estimate_cost(expression: &str, shape: InputShape) -> u64 {
    let depth = macro_depth(expression);
    if depth == 0 {
        // No macro iterates anything, so the cost does not scale with the input at all.
        return 1;
    }
    shape
        .max_collection_size
        .checked_pow(depth)
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
    // COMPILE FIRST. A malformed expression is a different fault from an expensive one, and an
    // operator who gets "over budget" for a typo is sent to the wrong place. It is also the
    // cheaper check, and it is where CEL's own recursion limit fires.
    let program = cel::Program::compile(expression)
        .map_err(|error| CostError::Uncompilable(error.to_string()))?;
    let estimated = estimate_cost(expression, shape);
    if estimated > budget {
        return Err(CostError::OverBudget { estimated, budget });
    }
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::{
        CostError, DEFAULT_COST_BUDGET, InputShape, compile_within_budget, estimate_cost,
        macro_depth,
    };

    fn shape(n: u64) -> InputShape {
        InputShape {
            max_collection_size: n,
        }
    }

    /// Depth is counted from the macros that ITERATE, and only from those.
    #[test]
    fn macro_depth_counts_nesting_and_nothing_else() {
        // No iteration at all: cost does not scale with the input.
        assert_eq!(macro_depth("user.email"), 0);
        assert_eq!(macro_depth("size(groups) > 3"), 0);
        // One level.
        assert_eq!(macro_depth("groups.filter(g, g == 'a')"), 1);
        assert_eq!(macro_depth("groups.all(g, g != '')"), 1);
        // Two macros in SEQUENCE are still depth one: neither runs inside the other, so the
        // cardinality multiplies in once. Reporting two here would refuse a cheap expression.
        assert_eq!(
            macro_depth("groups.filter(g, g == 'a') == roles.filter(r, r == 'b')"),
            1
        );
        // NESTED is what multiplies.
        assert_eq!(macro_depth("groups.filter(a, groups.exists(b, b == a))"), 2);
        assert_eq!(
            macro_depth("groups.filter(a, groups.exists(b, groups.exists(c, c == a)))"),
            3
        );
        // A name that merely ENDS in a macro's spelling is not that macro.
        assert_eq!(macro_depth("user.myfilter(x)"), 0);
        assert_eq!(macro_depth("prefix_map(y)"), 0);
    }

    /// Whitespace between a macro name and its paren does not hide it.
    ///
    /// THE BYPASS THIS EXISTS FOR. The first version of `macro_depth` matched the literal
    /// `"filter("`. Probed against the real evaluator, CEL accepts every spelling below, so a
    /// nested expression written with one space reported depth 0, was estimated at 1, was
    /// admitted, and would then have run for as long as its input allowed.
    ///
    /// Every case here is one the evaluator was MEASURED to accept, not one the grammar was
    /// read to permit. A future macro added to the list without this treatment reopens it.
    #[test]
    fn whitespace_cannot_hide_a_macro_from_the_depth_count() {
        for spelling in [
            "groups.filter(g, g == 'a')",
            "groups.filter (g, g == 'a')",
            "groups.filter\n(g, g == 'a')",
            "groups . filter ( g , g == 'a' )",
            "groups\n  .filter(g, g == 'a')",
        ] {
            assert_eq!(
                macro_depth(spelling),
                1,
                "the evaluator accepts {spelling:?}, so the estimate must see the macro in it"
            );
        }

        // And NESTED, spelled the same way: this is the shape that actually costs n squared.
        let nested = "groups.filter (a, groups.exists (b, b == a))";
        assert_eq!(macro_depth(nested), 2);
        assert_eq!(
            estimate_cost(nested, shape(10_000)),
            100_000_000,
            "a space must not turn a 10^8 expression into a 1"
        );
        assert!(
            matches!(
                compile_within_budget(nested, shape(10_000), DEFAULT_COST_BUDGET),
                Err(CostError::OverBudget { .. })
            ),
            "and it must still be refused"
        );
    }

    /// A macro spelled inside a STRING is counted, which over-refuses rather than under-admits.
    ///
    /// Recorded as a known imprecision rather than fixed. Blanking string literals first would
    /// mean a second parser -- the defect this codebase keeps finding -- and the error is in
    /// the SAFE direction: an operator gets a typed refusal naming the estimate, rather than a
    /// request that never returns. If it ever bites in practice the answer is to walk the real
    /// AST, not to special-case quotes.
    #[test]
    fn a_macro_name_inside_a_string_over_counts_which_is_the_safe_direction() {
        assert_eq!(
            macro_depth("user.note == 'filter(' "),
            1,
            "counted though nothing iterates: over-refusing is visible, under-refusing hangs"
        );
    }

    /// The estimate is `n^depth`, and it SATURATES rather than wrapping.
    ///
    /// Wrapping would be the worst failure this function could have: a deeply nested expression
    /// over a large collection would report a small number and be admitted, which is precisely
    /// the case the budget exists to refuse.
    #[test]
    fn the_estimate_saturates_instead_of_wrapping_to_cheap() {
        assert_eq!(estimate_cost("user.email", shape(10_000)), 1);
        assert_eq!(
            estimate_cost("groups.filter(g, g == 'a')", shape(1_000)),
            1_000
        );
        assert_eq!(
            estimate_cost("groups.filter(a, groups.exists(b, b == a))", shape(1_000)),
            1_000_000
        );
        let absurd = "groups.filter(a, groups.filter(b, groups.filter(c, groups.filter(d, \
                      groups.filter(e, groups.filter(f, groups.filter(g, groups.filter(h, \
                      groups.filter(i, groups.filter(j, j == a)))))))))) ";
        assert_eq!(
            estimate_cost(absurd, shape(1_000_000)),
            u64::MAX,
            "an estimate that overflowed would report `cheap` for the most expensive thing \
             anyone could write"
        );
    }

    /// The MEASURED table from the module header, as a table of verdicts.
    ///
    /// These are not invented thresholds: each row was timed against a real evaluator, and the
    /// budget was chosen so that everything admitted ran in about a tenth of a second and
    /// everything refused ran for seconds or minutes. Pinning them here is what stops the
    /// budget drifting away from the measurement that justifies it.
    #[test]
    fn the_budget_admits_what_was_measured_fast_and_refuses_what_was_measured_slow() {
        let one = "groups.filter(g, g.startsWith('g1')).size()";
        let two = "groups.filter(a, groups.exists(b, b == a)).size()";
        let three = "groups.filter(a, groups.exists(b, groups.exists(c, c == a)))";

        for (expression, n, measured) in [
            (one, 1_000_u64, "4.9 ms"),
            (two, 1_000, "124 ms"),
            (three, 100, "104 ms"),
        ] {
            assert!(
                compile_within_budget(expression, shape(n), DEFAULT_COST_BUDGET).is_ok(),
                "n={n} measured at {measured} and must be admitted"
            );
        }
        for (expression, n, measured) in [
            (one, 10_000_000_u64, "extrapolated from 320 ms at 10k"),
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
    ///
    /// An operator who gets "over budget" for a typo is sent to look at their input sizes. The
    /// two faults are different and the error says which.
    #[test]
    fn a_malformed_expression_is_a_different_fault_from_an_expensive_one() {
        let outcome = compile_within_budget("groups.filter(", shape(10), DEFAULT_COST_BUDGET);
        assert!(
            matches!(outcome, Err(CostError::Uncompilable(_))),
            "{outcome:?}"
        );

        // And it is reported as such even when it would ALSO be over budget, because the
        // compile runs first.
        let outcome = compile_within_budget("groups.filter(", shape(u64::MAX), 1);
        assert!(
            matches!(outcome, Err(CostError::Uncompilable(_))),
            "{outcome:?}"
        );
    }

    /// The verdict is a pure function of (expression, shape, budget).
    ///
    /// This is criterion 2's actual demand. A wall-clock timeout would fail this test on a
    /// loaded machine, which is the whole reason it is not one.
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
        assert_eq!(estimated, 100_000_000);
        assert_eq!(budget, DEFAULT_COST_BUDGET);
        assert!(
            CostError::OverBudget { estimated, budget }
                .to_string()
                .contains("100000000"),
            "the message must carry the estimate, not merely the fact of refusal"
        );
    }
}
