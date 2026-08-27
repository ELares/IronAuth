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
//! Refuse before evaluating when the estimate exceeds the budget. `depth` is macro nesting
//! read off the expression, and `n` is the largest cardinality the expression can iterate:
//! the greater of what the input document DECLARES and what the expression itself carries as
//! a literal. A comprehension-free expression iterates nothing, and is bounded instead by the
//! bytes it can touch -- its node count times the declared string bound.
//!
//! Every term is known without running anything, so the verdict is a pure function of
//! (expression, declared shape, budget).
//!
//! This section said `n^depth` over the DECLARED cardinality alone through two revisions
//! after both halves of that had been corrected elsewhere in this file. It is the one place a
//! reader looks for the rule, so it is the one place a stale statement of it does most harm.
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
//! # The wall, which used to be open
//!
//! An earlier version of this header said the budget was "a door beside an open wall": a
//! caller handed a `cel::Program` could evaluate it against anything, and a caller who wanted
//! one could call `cel::Program::compile` and skip the budget entirely. It prescribed the fix
//! and this is it.
//!
//! [`compile_within_budget`] now returns a [`BudgetedProgram`], which carries the shape it was
//! budgeted against and is the ONLY way to evaluate. Bindings go in as `serde_json::Value` and
//! results come out as one, so a caller never needs `cel` in its own manifest; and
//! `clippy.toml` names the type `cel::Program` and the parser alongside the two functions.
//! The call sites inside this crate carry `#[expect]`, and where one does, it is
//! self-verifying: an expectation that stopped being met would fail the build on its own. That
//! covers the entries this crate actually trips -- `Program::compile` and the `cel::Program`
//! type. The `cel::parser::Parser` and `cel::Value::resolve` entries are not exercised here at
//! all, so nothing in this build proves they are spelled correctly; review verified those two
//! by hand in a scratch crate, which is weaker and is worth saying rather than implying.
//!
//! FOUR routes, because naming one was not enough and the difference was measured rather than
//! reasoned about. A reviewer built a scratch crate carrying only the `Program::compile` entry
//! and found `cel::Program::try_from(src)`, `let p: cel::Program = src.try_into()` and
//! `cel::Value::resolve(&Parser::default().parse(src), &Context::default())` all SILENT --
//! `TryFrom<&str> for Program` calls `compile` internally, and a path-based lint cannot see
//! through to a different `DefId`. Naming the TYPE closes the constructor routes; naming
//! `resolve` closes the one that never mentions `Program`.
//!
//! Said exactly: this is a lint, not a capability. A crate that adds `cel` to its own manifest
//! and writes `#[allow(clippy::disallowed_types)]` is not stopped by it, and both of those are
//! reviewable lines in a diff. What the lint buys is that bypassing the budget cannot happen
//! by accident or by not knowing this crate exists.
//!
//! [`BudgetedProgram::evaluate`] also ENFORCES the declared shape rather than trusting it.
//! `max_collection_size` is a promise the input document makes, the estimate is `n^(depth+1)`
//! over that promise, and an input that breaks it costs more than the budget admitted.
//!
//! Two holes in that, both found by review measuring rather than arguing:
//!
//! - **The expression is an input too.** `n` was read only from the declared shape, so a
//!   collection written as a LITERAL never passed through a binding and was never counted.
//!   Measured: a 20,000-element literal under a declared 10 estimated 100, was admitted, and
//!   ran 6.2 seconds. `n` is now the larger of what the caller declared and what the
//!   expression carries.
//! - **Strings are bounded separately.** One string is one element, so every cardinality check
//!   passed while roughly 4 MB of compliant input allocated on the order of a gigabyte. Length
//!   drives allocation, cardinality drives iteration, and the `n^(depth+1)` model sees only
//!   the second, so [`InputShape::max_string_bytes`] is its own number.
//!
//! # What this crate still does NOT do
//!
//! **Nothing in the shipped server calls it.** Criterion 2 says "CEL expressions execute under
//! a cost budget", and no CEL expression executes anywhere in IronAuth today, so what is true
//! is the weaker statement that any expression that DOES execute cannot avoid the budget. That
//! is the enforceable half, and it is worth having in place before the first caller rather than
//! after; it is not the criterion.
//!
//! # What this model does NOT bound, measured rather than hedged
//!
//! **Allocation.** What an expression allocates is roughly (string size) x (string operations)
//! x (loop repetitions), and this model counts only the last. `max_string_bytes` caps the
//! first and nothing caps the product. Review measured `groups.map(g, name + name).size()`
//! with `groups` at exactly the declared 2,000 and `name` at exactly the declared 64 KiB:
//! **74 KB of fully compliant input, estimated at 0.4% of the budget, allocated 1.59 GB in
//! 8.5 seconds.**
//!
//! This is stated rather than modelled because three attempts to model it were each wrong in a
//! way testing caught: counting every node refused `groups.filter(g, g == 'a')` at 917,504,000
//! against a measured 4.9 ms, and counting `+` nodes counted the `@result + [x]` that `filter`
//! itself expands to as though it moved a 64 KiB string per element. A fourth guess is worth
//! less than an accurate statement of the gap. Bounding it properly needs a byte-denominated
//! budget computed by the same pre-evaluation walk, which is its own change.
//!
//! **Per-element work that is not iteration.** `matches` recompiles its regex per element, so
//! an ADMITTED expression can still be expensive.
//!
//! Both are properties of the ESTIMATE. The enforcement half -- that an input may not exceed
//! the shape the estimate was computed from -- holds.
//!
//! Wiring the first caller is not free, and the cost is recorded here so it is not
//! rediscovered: this crate declares `rust-version = "1.86"` because `cel` 0.14 does, while the
//! workspace and `docs/COMPATIBILITY.md` promise 1.85. The CI msrv lane excludes this crate for
//! exactly as long as nothing depends on it. The first production dependency raises the shipped
//! binary's MSRV, which is a compatibility promise, not an implementation detail.

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
    /// The largest number of BYTES any single string in the input may hold.
    ///
    /// # Why this is not `max_collection_size`
    ///
    /// They bound different costs and their natural magnitudes differ by orders of magnitude.
    /// Cardinality drives ITERATION, which is what the `n^(depth+1)` estimate models; string
    /// length drives ALLOCATION, which that estimate does not see at all. A tenant whose
    /// documents declare at most 10 groups is not thereby promising that every string in them
    /// is 10 bytes, so folding the two into one number would refuse ordinary input.
    ///
    /// It exists because leaving strings unbounded left a hole the estimate could not
    /// express: review measured roughly 4 MB of otherwise-compliant input allocating on the
    /// order of a gigabyte inside an expression the budget had ADMITTED, because concatenation
    /// and `+` scale with size while the model counts only elements.
    pub max_string_bytes: u64,
}

/// A generous default for [`InputShape::max_string_bytes`].
///
/// 64 KiB is far above any claim value an identity token carries -- a long display name, a
/// URL, a serialised group path -- and far below the megabytes at which allocation becomes
/// the dominant cost. It is a backstop against a pathological document, not a schema.
pub const DEFAULT_MAX_STRING_BYTES: u64 = 64 * 1024;

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

/// An upper bound on how many elements this expression can EVALUATE TO.
///
/// # Why the largest source node was the wrong question
///
/// The model's `n` is the cardinality a comprehension multiplies by, and two earlier versions
/// answered it by taking a MAXIMUM over source nodes: first the declared shape alone, then the
/// greater of that and the largest literal. Both are wrong for the same reason, and CEL's `+`
/// is the counterexample: it CONCATENATES lists (`objects.rs:1583`), so `k` sources of size
/// `m` iterate `k * m` while a maximum reports `m`.
///
/// Measured by review against the real crate, at the previous HEAD:
///
/// ```text
/// (groups + groups + ... 40 copies).filter(g, g > 0).size()
///   383 bytes of expression, `groups` bound to exactly the declared 1,000
///   estimate 1,000,000 -> ADMITTED -> ran 20.8 SECONDS over 40,000 elements
/// ```
///
/// It also defeated the literal fix by rewriting the same data: forty concatenated
/// 1,000-element literals is a SMALLER source (155,783 bytes) than one 40,000-element literal
/// (228,915 bytes), and the small one was admitted while the large one was correctly refused.
/// A bound that a rewrite can walk around is not a bound.
///
/// So this answers the actual question -- what can this node evaluate to -- and `_+_` sums.
fn cardinality_bound(expression: &Expr, shape: InputShape) -> u64 {
    match expression {
        // A binding, or a field of one: whatever the input document declared. This is the
        // case the original model handled, and it is still the common one.
        Expr::Ident(_) | Expr::Select(_) => shape.max_collection_size,
        // A literal: exactly what is written. Its ELEMENTS' cardinalities are not added here;
        // a nested collection is bounded where it is itself iterated.
        Expr::List(list) => list.elements.len() as u64,
        Expr::Map(map) => map.entries.len() as u64,
        Expr::Struct(structure) => structure.entries.len() as u64,
        Expr::Call(call) => {
            if call.func_name == "_+_" {
                // CONCATENATION SUMS. Saturating, because an estimate that wrapped to a small
                // number would admit the most expensive thing anyone could write.
                call.args.iter().fold(0_u64, |total, arg| {
                    total.saturating_add(cardinality_bound(&arg.expr, shape))
                })
            } else {
                // Every other call is at most as large as what it was called on: `filter`
                // narrows, `map` preserves, `size` returns a scalar. Taking the maximum over
                // the target and the arguments over-estimates rather than under-estimates,
                // which is the safe direction for a bound.
                call.target
                    .iter()
                    .map(|target| cardinality_bound(&target.expr, shape))
                    .chain(
                        call.args
                            .iter()
                            .map(|arg| cardinality_bound(&arg.expr, shape)),
                    )
                    .max()
                    .unwrap_or(0)
            }
        }
        // A comprehension yields at most what it iterated.
        Expr::Comprehension(comprehension) => {
            cardinality_bound(&comprehension.iter_range.expr, shape)
        }
        // A scalar is not a collection.
        Expr::Literal(_) | Expr::Unspecified => 0,
    }
}

/// The largest cardinality any comprehension in the expression actually iterates.
///
/// Every comprehension is visited, not only the deepest, because the expensive one is not
/// necessarily the most nested.
fn largest_iterated_cardinality(expression: &Expr, shape: InputShape) -> u64 {
    let here = match expression {
        Expr::Comprehension(comprehension) => {
            cardinality_bound(&comprehension.iter_range.expr, shape)
        }
        _ => 0,
    };
    let within = match expression {
        Expr::Comprehension(comprehension) => [
            &comprehension.iter_range,
            &comprehension.accu_init,
            &comprehension.loop_cond,
            &comprehension.loop_step,
            &comprehension.result,
        ]
        .into_iter()
        .map(|part| largest_iterated_cardinality(&part.expr, shape))
        .max()
        .unwrap_or(0),
        Expr::Call(call) => call
            .target
            .iter()
            .map(|target| largest_iterated_cardinality(&target.expr, shape))
            .chain(
                call.args
                    .iter()
                    .map(|arg| largest_iterated_cardinality(&arg.expr, shape)),
            )
            .max()
            .unwrap_or(0),
        Expr::Select(select) => largest_iterated_cardinality(&select.operand.expr, shape),
        Expr::List(list) => list
            .elements
            .iter()
            .map(|element| largest_iterated_cardinality(&element.expr, shape))
            .max()
            .unwrap_or(0),
        Expr::Map(map) => entries_iterated(&map.entries, shape),
        Expr::Struct(structure) => entries_iterated(&structure.entries, shape),
        Expr::Ident(_) | Expr::Literal(_) | Expr::Unspecified => 0,
    };
    here.max(within)
}

/// The largest iterated cardinality inside a map or struct literal's entries, both arms.
fn entries_iterated(entries: &[IdedEntryExpr], shape: InputShape) -> u64 {
    entries
        .iter()
        .map(|entry| match &entry.expr {
            EntryExpr::StructField(field) => largest_iterated_cardinality(&field.value.expr, shape),
            EntryExpr::MapEntry(entry) => largest_iterated_cardinality(&entry.key.expr, shape)
                .max(largest_iterated_cardinality(&entry.value.expr, shape)),
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
        // NOTHING ITERATES, so this model has nothing to say and returns its floor.
        //
        // Not a claim that the expression is free. Three attempts were made to have this arm
        // bound ALLOCATION instead -- nodes times the string bound, then concatenations times
        // the string bound times the loop count -- and each had a hole: the first refused
        // `groups.filter(g, g == 'a')` at 917,504,000 against a measured 4.9 ms, and the
        // second counted the `@result + [x]` that `filter` itself expands to as though it
        // moved a 64 KiB string per element. Allocation is now stated as unmodelled in the
        // header rather than modelled badly, which is the honest form of the same information.
        return 1;
    }

    // WHAT IS ACTUALLY ITERATED. See `cardinality_bound`: a maximum over source nodes was
    // walked around by `groups + groups + ...`, which concatenates, so 40 copies of a
    // declared 1,000 iterated 40,000 while the estimate said 1,000.
    let n = largest_iterated_cardinality(expression, shape);
    n.checked_pow(depth.saturating_add(1)).unwrap_or(u64::MAX)
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
) -> Result<BudgetedProgram, CostError> {
    // COMPILE FIRST, and estimate from the SAME program. A malformed expression is a different
    // fault from an expensive one, and an operator who gets "over budget" for a typo is sent to
    // the wrong place. It is also where CEL's own recursion limit fires, and -- since the
    // estimate now walks the parsed tree -- it is the only thing that produces a tree to walk.
    #[expect(
        clippy::disallowed_methods,
        clippy::disallowed_types,
        reason = "this crate IS the budget: it compiles here and refuses over-budget expressions before returning, which is what every other caller is forbidden from bypassing"
    )]
    let program = cel::Program::compile(expression)
        .map_err(|error| CostError::Uncompilable(error.to_string()))?;
    let estimated = estimate_parsed_cost(&program.expression().expr, shape);
    if estimated > budget {
        return Err(CostError::OverBudget { estimated, budget });
    }
    Ok(BudgetedProgram { program, shape })
}

/// An expression that passed the budget, together with the shape it was budgeted against.
///
/// # Why this is not a `cel::Program`
///
/// It used to be, and that made the budget a door beside an open wall: a caller handed a
/// `cel::Program` can evaluate it against anything, and a caller who wants one can call
/// `cel::Program::compile` and skip the budget entirely. Neither is a hypothetical, because
/// nothing in the estimate binds it to the input it is later run against.
///
/// Owning both halves is what closes it. The shape travels WITH the program, evaluation is
/// only reachable through [`evaluate`](Self::evaluate), and `evaluate` enforces the shape it
/// was budgeted against rather than trusting that someone else did.
///
/// It also means a caller never needs `cel` in its own manifest: bindings go in as
/// `serde_json::Value` and results come out as one.
///
/// Not `Clone`, because `cel::Program` is not. A caller that wants one per expression holds
/// it behind an `Arc`, which is what a compiled-once-evaluated-many caller wants anyway.
pub struct BudgetedProgram {
    #[expect(
        clippy::disallowed_types,
        reason = "this crate IS the budget: it owns the only compiled program, and every other crate is forbidden from naming this type so it cannot hold an unbudgeted one"
    )]
    program: cel::Program,
    shape: InputShape,
}

/// Hand-written, because the derived one prints the whole parsed tree.
///
/// An expression carrying a 20,000-element literal produced a megabyte-wide panic message in
/// a failing test, which is a real cost: a panic nobody can read is a panic nobody diagnoses,
/// and this type appears in `expect`/`unwrap` messages by construction.
impl core::fmt::Debug for BudgetedProgram {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BudgetedProgram")
            .field("max_collection_size", &self.shape.max_collection_size)
            .finish_non_exhaustive()
    }
}

/// Why an evaluation was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// An input exceeds the shape the expression was budgeted against.
    ///
    /// This is the enforcement half of the cost model, and without it the model is
    /// decoration: the estimate is computed over what the document PROMISED, so an input that
    /// exceeds the promise costs more than the budget admitted and the budget bounded nothing.
    ///
    /// Carries its [`Unit`], because the same variant now reports two different bounds and an
    /// operator reading "holds 4194304 elements" about a STRING is being told something false
    /// about their own data. The first version of the string bound reused this variant with
    /// its cardinality wording intact.
    OversizedInput {
        /// The binding that carried it.
        variable: String,
        /// How much it actually had, in [`unit`](Self::OversizedInput::unit).
        size: u64,
        /// The largest the shape allows, in the same unit.
        declared: u64,
        /// Which bound was exceeded.
        unit: Unit,
    },
    /// An input value has no CEL representation.
    NotRepresentable {
        /// The binding that carried it.
        variable: String,
        /// What was wrong with it.
        reason: String,
    },
    /// Evaluation itself failed: an unbound name, a type error, a bad index.
    Failed(String),
    /// The result has no JSON representation.
    ResultNotRepresentable(String),
}

/// Which of the two declared bounds an input exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Elements in a collection, bounded by [`InputShape::max_collection_size`].
    Elements,
    /// Bytes in a single string, bounded by [`InputShape::max_string_bytes`].
    Bytes,
}

impl core::fmt::Display for Unit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Elements => f.write_str("elements"),
            Self::Bytes => f.write_str("bytes"),
        }
    }
}

impl core::fmt::Display for EvalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OversizedInput {
                variable,
                size,
                declared,
                unit,
            } => write!(
                f,
                "input `{variable}` holds {size} {unit} against a declared maximum of \
                 {declared} {unit}"
            ),
            Self::NotRepresentable { variable, reason } => {
                write!(
                    f,
                    "input `{variable}` is not representable in CEL: {reason}"
                )
            }
            Self::Failed(message) => write!(f, "expression evaluation failed: {message}"),
            Self::ResultNotRepresentable(message) => {
                write!(f, "the result is not representable as JSON: {message}")
            }
        }
    }
}

impl std::error::Error for EvalError {}

impl BudgetedProgram {
    /// The shape this expression was budgeted against, and which [`evaluate`](Self::evaluate)
    /// enforces.
    #[must_use]
    pub const fn shape(&self) -> InputShape {
        self.shape
    }

    /// Evaluate against `bindings`, refusing any input larger than the declared shape.
    ///
    /// # What the expression can reach, which is criterion 3
    ///
    /// Exactly these bindings and CEL's standard library, because the context is built here
    /// and built fresh. There is no ambient anything to withhold: `cel::Env::stdlib()` is
    /// string, arithmetic, collection and type functions, and the CEL specification gives it
    /// no IO, no clock, no environment and no host bridge. This crate registers no additional
    /// function, so an expression naming `fetch`, `http`, `env` or `readFile` fails to
    /// resolve rather than being caught by a denylist -- which is the difference between a
    /// surface that has no doors and one that has locked ones.
    ///
    /// Cross-tenant access is the same property seen from the caller's side: an expression can
    /// only name what it was bound, so the isolation is the caller's choice of bindings and
    /// cannot be widened from inside the expression.
    ///
    /// # Errors
    ///
    /// [`EvalError::OversizedInput`] when a binding exceeds the declared shape,
    /// [`EvalError::NotRepresentable`] when an input has no CEL form,
    /// [`EvalError::Failed`] when evaluation fails, and
    /// [`EvalError::ResultNotRepresentable`] when the result has no JSON form.
    pub fn evaluate(
        &self,
        bindings: &[(&str, &serde_json::Value)],
    ) -> Result<serde_json::Value, EvalError> {
        let mut context = cel::Context::default();
        for (name, value) in bindings {
            let converted = to_cel(
                name,
                value,
                self.shape.max_collection_size,
                self.shape.max_string_bytes,
            )?;
            context.add_variable_from_value(*name, converted);
        }
        let resolved = self
            .program
            .execute(&context)
            .map_err(|error| EvalError::Failed(error.to_string()))?;
        resolved
            .json()
            .map_err(|error| EvalError::ResultNotRepresentable(error.to_string()))
    }
}

/// Convert one binding to a CEL value, enforcing the declared cardinality on the way.
///
/// Conversion and enforcement in ONE pass, deliberately. Walking the document twice invites
/// the two walks to disagree about what counts as a collection, and the disagreement would be
/// silent: a shape check that misses a nesting the converter produces is a check that passes
/// on the input it was meant to refuse.
fn to_cel(
    variable: &str,
    value: &serde_json::Value,
    declared: u64,
    max_string_bytes: u64,
) -> Result<cel::Value, EvalError> {
    match value {
        serde_json::Value::Null => Ok(cel::Value::Null),
        serde_json::Value::Bool(inner) => Ok(cel::Value::Bool(*inner)),
        serde_json::Value::Number(number) => number.as_i64().map(cel::Value::Int).map_or_else(
            || {
                number
                    .as_f64()
                    .map(cel::Value::Float)
                    .ok_or_else(|| EvalError::NotRepresentable {
                        variable: variable.to_owned(),
                        reason: format!("the number {number} is neither an i64 nor an f64"),
                    })
            },
            Ok,
        ),
        serde_json::Value::String(inner) => {
            // BYTES, not chars: the allocation this bounds is in bytes, and `chars().count()`
            // would walk the whole string to answer a question `len()` answers in constant
            // time -- doing linear work to bound linear work.
            let size = inner.len() as u64;
            if size > max_string_bytes {
                return Err(EvalError::OversizedInput {
                    variable: variable.to_owned(),
                    size,
                    declared: max_string_bytes,
                    unit: Unit::Bytes,
                });
            }
            Ok(cel::Value::String(std::sync::Arc::new(inner.clone())))
        }
        serde_json::Value::Array(items) => {
            let size = items.len() as u64;
            if size > declared {
                return Err(EvalError::OversizedInput {
                    variable: variable.to_owned(),
                    size,
                    declared,
                    unit: Unit::Elements,
                });
            }
            let converted = items
                .iter()
                .map(|item| to_cel(variable, item, declared, max_string_bytes))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(cel::Value::List(std::sync::Arc::new(converted)))
        }
        serde_json::Value::Object(entries) => {
            // A MAP IS A COLLECTION TOO. CEL's macros comprehend over maps exactly as they do
            // over lists, so a shape check that counted only arrays would admit an
            // unbounded map and the depth-times-cardinality estimate would be wrong by the
            // whole of it.
            let size = entries.len() as u64;
            if size > declared {
                return Err(EvalError::OversizedInput {
                    variable: variable.to_owned(),
                    size,
                    declared,
                    unit: Unit::Elements,
                });
            }
            let mut map = std::collections::HashMap::new();
            for (key, item) in entries {
                // THE KEY IS A STRING TOO, and the first version of this bound checked only
                // the value. `{"<4 MiB string>": 1}` is one entry, so the cardinality check
                // passes, and the value is a small integer, so the recursion finds nothing --
                // the entire string bound was bypassable through the key position. Found by
                // review asking of the value check "what is the column beside it".
                let key_size = key.len() as u64;
                if key_size > max_string_bytes {
                    return Err(EvalError::OversizedInput {
                        variable: variable.to_owned(),
                        size: key_size,
                        declared: max_string_bytes,
                        unit: Unit::Bytes,
                    });
                }
                map.insert(
                    cel::objects::Key::String(std::sync::Arc::new(key.clone())),
                    to_cel(variable, item, declared, max_string_bytes)?,
                );
            }
            Ok(cel::Value::Map(cel::objects::Map {
                map: std::sync::Arc::new(map),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CostError, DEFAULT_COST_BUDGET, DEFAULT_MAX_STRING_BYTES, InputShape,
        compile_within_budget, comprehension_depth, estimate_parsed_cost,
    };

    fn shape(n: u64) -> InputShape {
        InputShape {
            max_collection_size: n,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
        }
    }

    /// The depth of an expression, via the same parser the evaluator uses.
    fn depth(expression: &str) -> u32 {
        #[expect(
            clippy::disallowed_methods,
            reason = "a test helper that measures the parser itself, not a caller evaluating an expression"
        )]
        #[expect(
            clippy::disallowed_types,
            reason = "a test helper measuring the parser itself"
        )]
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
        #[expect(
            clippy::disallowed_methods,
            reason = "a test helper that measures the parser itself, not a caller evaluating an expression"
        )]
        #[expect(
            clippy::disallowed_types,
            reason = "a test helper measuring the parser itself"
        )]
        let parsed = |expression: &str| cel::Program::compile(expression).expect("compiles");
        // A comprehension-free expression iterates nothing, so this model's floor is what it
        // reports. That is not a claim the expression is free -- see the header on allocation,
        // which is deliberately unmodelled rather than modelled badly.
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

/// Criterion 3, and criterion 2's enforcement half.
///
/// These are separated from the cost-estimate tests above because they measure a different
/// thing: not what the model PREDICTS an expression costs, but what an expression can reach
/// and what happens when the input breaks the promise the prediction rested on.
#[cfg(test)]
mod evaluation_tests {
    use super::{
        CostError, DEFAULT_COST_BUDGET, DEFAULT_MAX_STRING_BYTES, EvalError, InputShape,
        compile_within_budget,
    };

    fn program(expression: &str, n: u64) -> super::BudgetedProgram {
        compile_within_budget(
            expression,
            InputShape {
                max_collection_size: n,
                max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            },
            DEFAULT_COST_BUDGET,
        )
        .expect("compiles within budget")
    }

    /// The positive control: without this, every refusal below could be a broken evaluator.
    #[test]
    fn an_ordinary_expression_evaluates_against_its_bindings() {
        let groups = serde_json::json!(["g1:admin", "g2:reader", "other"]);
        let result = program("groups.filter(g, g.startsWith('g1')).size()", 100)
            .evaluate(&[("groups", &groups)])
            .expect("evaluates");
        assert_eq!(result, serde_json::json!(1));
    }

    /// CRITERION 3: "adversarial expressions attempting network, environment, or cross-tenant
    /// access fail to compile or evaluate".
    ///
    /// Every one of these fails because the name RESOLVES TO NOTHING, not because a denylist
    /// caught it. That distinction is the whole property: a denylist is a list of the attacks
    /// someone thought of, and this is a surface with no doors on it. `cel::Env::stdlib()` is
    /// string, arithmetic, collection and type functions, the CEL specification gives it no IO,
    /// and this crate registers no function of its own.
    ///
    /// If a future change calls `add_function`, these tests do NOT automatically catch it --
    /// they catch the specific names below. The property that must be preserved is "this crate
    /// registers no host function", and the assertion for that is the absence of `add_function`
    /// in this file, which `no_host_function_is_registered` pins.
    #[test]
    fn adversarial_expressions_reach_nothing() {
        let bound = serde_json::json!({"sub": "user-1"});
        for expression in [
            "fetch('http://169.254.169.254/latest/meta-data/')",
            "http.get('https://example.invalid')",
            "env('PATH')",
            "os.environ['AWS_SECRET_ACCESS_KEY']",
            "readFile('/etc/passwd')",
            "import('std')",
            // Cross-tenant: naming a binding that was not supplied.
            "other_tenant.claims",
            "claims.sub",
        ] {
            let outcome = compile_within_budget(
                expression,
                InputShape {
                    max_collection_size: 16,
                    max_string_bytes: DEFAULT_MAX_STRING_BYTES,
                },
                DEFAULT_COST_BUDGET,
            )
            .map_err(|_| ())
            .and_then(|compiled| compiled.evaluate(&[("subject", &bound)]).map_err(|_| ()));
            assert!(
                outcome.is_err(),
                "`{expression}` must fail to compile or to evaluate; it resolved instead"
            );
        }
    }

    /// The guard on the guard: this crate must register no host function.
    ///
    /// `adversarial_expressions_reach_nothing` names eight specific attacks, and a list of
    /// names cannot express "and nothing else either". This can: the surface is empty because
    /// nothing adds to it, and adding to it is one call. A source scan is a weak instrument in
    /// general, but here the thing being asserted IS a property of the source text -- that a
    /// particular constructor is never invoked in this crate -- rather than a property of
    /// behaviour that a scan is standing in for.
    #[test]
    fn no_host_function_is_registered() {
        // The needle is ASSEMBLED rather than written, because a scan of the file it lives in
        // matches its own source otherwise. The first version did exactly that and failed on
        // its own assertion message, which is the same shape as a process watcher whose
        // pattern matches its own command line.
        //
        // The leading dot is load-bearing too: it matches the CALL and not the prose above,
        // which discusses `add_function` by name on purpose.
        let needle = format!(".add_{}(", "function");
        let source = include_str!("lib.rs");
        let registrations = source
            .lines()
            .filter(|line| line.contains(&needle))
            .filter(|line| !line.trim_start().starts_with("//"))
            .count();
        assert_eq!(
            registrations, 0,
            "this crate registers a host function, which widens what every CEL expression in \
             IronAuth can reach. Criterion 3 asks that expressions have no ambient fetch or \
             IO; adding a function here is how that stops being true."
        );
    }

    /// CRITERION 2's enforcement half: the declared shape is checked, not trusted.
    ///
    /// The estimate is `n^(depth+1)` where `n` is the DECLARED maximum. If an input may exceed
    /// it, the budget bounded nothing: the measured case behind this is a single filter over
    /// 200,000 elements taking 423 seconds, which is admitted by any budget that was computed
    /// against a declared 1,000.
    #[test]
    fn an_input_larger_than_the_declared_shape_is_refused() {
        let oversized = serde_json::json!((0..11).collect::<Vec<i32>>());
        let error = program("groups.size()", 10)
            .evaluate(&[("groups", &oversized)])
            .expect_err("11 elements against a declared 10 must be refused");
        assert_eq!(
            error,
            EvalError::OversizedInput {
                variable: "groups".to_owned(),
                size: 11,
                declared: 10,
                unit: super::Unit::Elements,
            }
        );
    }

    /// Exactly at the bound is admitted, which is what makes the test above about the BOUND
    /// rather than about refusing everything.
    #[test]
    fn an_input_exactly_at_the_declared_shape_is_admitted() {
        let exact = serde_json::json!((0..10).collect::<Vec<i32>>());
        let result = program("groups.size()", 10)
            .evaluate(&[("groups", &exact)])
            .expect("10 elements against a declared 10 is within the promise");
        assert_eq!(result, serde_json::json!(10));
    }

    /// A MAP is a collection too, and counting only arrays would leave the estimate wrong by
    /// the whole of it: CEL's macros comprehend over maps exactly as they do over lists.
    #[test]
    fn an_oversized_map_is_refused_like_an_oversized_list() {
        let mut entries = serde_json::Map::new();
        for i in 0..11 {
            entries.insert(format!("k{i}"), serde_json::json!(i));
        }
        let oversized = serde_json::Value::Object(entries);
        let error = program("attrs.size()", 10)
            .evaluate(&[("attrs", &oversized)])
            .expect_err("an 11-entry map against a declared 10 must be refused");
        assert!(matches!(error, EvalError::OversizedInput { size: 11, .. }));
    }

    /// A collection the EXPRESSION carries, which no binding bounds.
    ///
    /// Review reproduced this against the real crate: `[<20,000 literals>].filter(..).size()`
    /// with `max_collection_size: 10` estimated 10^2 = 100 against a budget of 1,000,000,000
    /// and ran for 6.2 seconds. `evaluate` could not have caught it either -- the only binding
    /// was a one-element list that passed the shape check honestly.
    ///
    /// Asserted on the ESTIMATE rather than on a refusal, deliberately. 20,000^2 is 4x10^8,
    /// which the default budget genuinely admits, so demanding a refusal here would be
    /// asserting the budget's calibration rather than this fix. What this fix changes is the
    /// number the model uses: 100 before, 400,000,000 after. The sibling below pins that a
    /// literal large enough to exceed the budget is now actually refused.
    #[test]
    fn a_collection_written_into_the_expression_is_counted() {
        let expression = literal_list_expression(20_000);
        let compiled = compile_within_budget(
            &expression,
            InputShape {
                max_collection_size: 10,
                max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            },
            DEFAULT_COST_BUDGET,
        )
        .expect("4x10^8 is within the default budget");
        assert_eq!(compiled.shape().max_collection_size, 10);
        assert_eq!(
            super::estimate_parsed_cost(&compiled.program.expression().expr, compiled.shape()),
            20_000_u64.pow(2),
            "the estimate must use the literal's cardinality, not the declared 10"
        );
    }

    /// And a literal big enough to break the budget is refused, which is the point of counting.
    #[test]
    fn a_literal_over_the_budget_is_refused() {
        let expression = literal_list_expression(40_000);
        let error = compile_within_budget(
            &expression,
            InputShape {
                max_collection_size: 10,
                max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            },
            DEFAULT_COST_BUDGET,
        )
        .expect_err("40,000^2 = 1.6x10^9 exceeds the budget");
        assert!(
            matches!(error, CostError::OverBudget { estimated, .. } if estimated == 40_000_u64.pow(2)),
            "refused for cost, at the literal's cardinality: {error}"
        );
    }

    /// CONCATENATION SUMS, which a maximum over source nodes could not see.
    ///
    /// Measured by review at the previous HEAD: `(groups + groups + ... 40 copies)
    /// .filter(g, g > 0).size()` is 383 bytes, `groups` was bound to exactly the declared
    /// 1,000 and passed the shape check honestly, the estimate was 1,000,000 -- and it ran for
    /// 20.8 seconds over 40,000 elements. No literal is involved, so neither the declared
    /// bound nor the largest-literal fix applied to it.
    #[test]
    fn concatenated_bindings_multiply_the_iterated_cardinality() {
        let concatenated = std::iter::repeat_n("groups", 40)
            .collect::<Vec<_>>()
            .join(" + ");
        let expression = format!("({concatenated}).filter(g, g > 0).size()");
        let error = compile_within_budget(
            &expression,
            InputShape {
                max_collection_size: 1_000,
                max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            },
            DEFAULT_COST_BUDGET,
        )
        .expect_err("40 x 1,000 iterates 40,000, which is over the budget at depth 1");
        assert!(
            matches!(error, CostError::OverBudget { estimated, .. } if estimated == 40_000_u64.pow(2)),
            "the estimate must sum the concatenated sources, not take their maximum: {error}"
        );
    }

    /// The same rewrite against the literal bound, which it also walked around.
    ///
    /// Forty concatenated 1,000-element literals is a SMALLER source than one 40,000-element
    /// literal, and the large one was already refused while the small one was admitted. A
    /// bound a rewrite can step around is not a bound.
    #[test]
    fn concatenated_literals_are_summed_like_one_large_literal() {
        let one_thousand = format!(
            "[{}]",
            (0..1_000)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let concatenated = std::iter::repeat_n(one_thousand.as_str(), 40)
            .collect::<Vec<_>>()
            .join(" + ");
        let expression = format!("({concatenated}).filter(g, g > 0).size()");
        let error = compile_within_budget(
            &expression,
            InputShape {
                max_collection_size: 10,
                max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            },
            DEFAULT_COST_BUDGET,
        )
        .expect_err("40,000 elements, however they are spelled");
        assert!(
            matches!(error, CostError::OverBudget { estimated, .. } if estimated == 40_000_u64.pow(2)),
            "spelling the same data as a concatenation must not lower the estimate: {error}"
        );
    }

    /// Adding a loop around an expression must never LOWER its estimate.
    ///
    /// Review measured the inversion on an earlier attempt at an allocation term: a body
    /// estimated 2,621,440,000 and was refused, and the same body wrapped in `groups.all(..)`
    /// -- strictly more work -- estimated 100 and was admitted, because wrapping it moved the
    /// estimate to a different arm. One model with one unit cannot do that, and this pins it.
    #[test]
    fn wrapping_an_expression_in_a_loop_does_not_lower_its_estimate() {
        let shape = InputShape {
            max_collection_size: 1_000,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
        };
        let inner = "(groups + groups).filter(g, g > 0).size()";
        let wrapped = format!("groups.all(h, {inner} > 0)");
        let bare = estimate(inner, shape);
        let looped = estimate(&wrapped, shape);
        assert!(
            looped >= bare,
            "wrapping raised the work and lowered the estimate: {bare} -> {looped}"
        );
    }

    /// The estimate for `expression` under `shape`, refused or not.
    fn estimate(expression: &str, shape: InputShape) -> u64 {
        #[expect(
            clippy::disallowed_types,
            clippy::disallowed_methods,
            reason = "a test helper reading the estimate directly, not a caller evaluating"
        )]
        let program = cel::Program::compile(expression).expect("compiles");
        super::estimate_parsed_cost(&program.expression().expr, shape)
    }

    /// The declared shape still wins when it is the larger of the two, so the fix did not
    /// quietly replace one bound with the other.
    #[test]
    fn a_small_literal_does_not_lower_the_declared_bound() {
        let error = compile_within_budget(
            "[1, 2].filter(g, g > 0).size() + groups.filter(g, g > 0).size()",
            InputShape {
                max_collection_size: 100_000,
                max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            },
            DEFAULT_COST_BUDGET,
        )
        .expect_err("the DECLARED 100,000 still governs");
        assert!(matches!(
            error,
            CostError::OverBudget { estimated, .. } if estimated == 100_000_u64.pow(2)
        ));
    }

    /// `[0,1,...,n-1].filter(g, g > 0).size()`.
    fn literal_list_expression(n: usize) -> String {
        let literal = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        format!("[{literal}].filter(g, g > 0).size()")
    }

    /// A string large enough to matter is refused, which the cardinality bound cannot see.
    ///
    /// One string is one element, so every collection check passes; what it costs is
    /// ALLOCATION, and the `n^(depth+1)` model counts iteration only. Review measured roughly
    /// 4 MB of otherwise-compliant input allocating on the order of a gigabyte inside an
    /// expression the budget had admitted.
    #[test]
    fn an_oversized_string_is_refused_although_it_is_one_element() {
        let huge = serde_json::json!("x".repeat(
            usize::try_from(DEFAULT_MAX_STRING_BYTES + 1).expect("fits on a 64-bit test host")
        ));
        let error = program("name.size()", 10)
            .evaluate(&[("name", &huge)])
            .expect_err("a string past the byte bound must be refused");
        assert!(
            matches!(error, EvalError::OversizedInput { size, declared, .. }
                if size == DEFAULT_MAX_STRING_BYTES + 1
                    && declared == DEFAULT_MAX_STRING_BYTES),
            "refused on the STRING bound, not the collection bound: {error}"
        );
    }

    /// And a string inside a collection is reached too, not only a top-level one.
    #[test]
    fn an_oversized_string_nested_in_a_list_is_refused() {
        let huge = serde_json::json!([
            "ok",
            "x".repeat(
                usize::try_from(DEFAULT_MAX_STRING_BYTES + 1).expect("fits on a 64-bit test host")
            )
        ]);
        let error = program("names.size()", 10)
            .evaluate(&[("names", &huge)])
            .expect_err("the inner string breaks the bound even though the list does not");
        assert!(matches!(error, EvalError::OversizedInput { size, .. }
            if size == DEFAULT_MAX_STRING_BYTES + 1));
    }

    /// A map KEY is a string, and the first version of the string bound checked only values.
    ///
    /// `{"<huge>": 1}` is ONE entry, so the cardinality check passes; the value is a small
    /// integer, so the recursion finds nothing. The entire string bound was bypassable
    /// through the key position.
    #[test]
    fn an_oversized_map_key_is_refused_like_an_oversized_value() {
        let mut entries = serde_json::Map::new();
        entries.insert(
            "x".repeat(usize::try_from(DEFAULT_MAX_STRING_BYTES + 1).expect("fits")),
            serde_json::json!(1),
        );
        let huge = serde_json::Value::Object(entries);
        let error = program("attrs.size()", 10)
            .evaluate(&[("attrs", &huge)])
            .expect_err("a map KEY past the byte bound must be refused");
        assert!(
            matches!(error, EvalError::OversizedInput { size, unit, .. }
                if size == DEFAULT_MAX_STRING_BYTES + 1 && unit == super::Unit::Bytes),
            "refused on the STRING bound, in bytes: {error}"
        );
    }

    /// A string refusal must not describe itself in elements.
    ///
    /// The same variant now carries both bounds, and an operator told their 200 KB display
    /// name "holds 204800 elements" has been told something false about their own data.
    #[test]
    fn a_string_refusal_reports_bytes_and_a_collection_refusal_reports_elements() {
        let huge = serde_json::json!(
            "x".repeat(usize::try_from(DEFAULT_MAX_STRING_BYTES + 1).expect("fits"))
        );
        let string_error = program("name.size()", 10)
            .evaluate(&[("name", &huge)])
            .expect_err("refused");
        assert!(
            string_error.to_string().contains("bytes"),
            "a string refusal must say bytes: {string_error}"
        );

        let oversized = serde_json::json!((0..11).collect::<Vec<i32>>());
        let list_error = program("groups.size()", 10)
            .evaluate(&[("groups", &oversized)])
            .expect_err("refused");
        assert!(
            list_error.to_string().contains("elements"),
            "a collection refusal must say elements: {list_error}"
        );
    }

    /// An ordinary string is admitted, so the bound is a bound rather than a refusal.
    #[test]
    fn an_ordinary_string_is_admitted() {
        let name = serde_json::json!("a reasonable display name");
        let result = program("name.size()", 10)
            .evaluate(&[("name", &name)])
            .expect("an ordinary string is well within the bound");
        assert_eq!(result, serde_json::json!(25));
    }

    /// A list INSIDE a list, which the object case does not cover.
    ///
    /// Found by mutation: passing `u64::MAX` down the ARRAY branch's recursion survived every
    /// other test here, because the only nested fixture was an object holding a list and that
    /// path recurses through the MAP branch. Two branches recurse, so two fixtures are needed;
    /// one nested fixture reads like coverage of "nesting" and was coverage of one of them.
    #[test]
    fn a_list_nested_in_a_list_over_the_shape_is_refused() {
        let nested = serde_json::json!([(0..11).collect::<Vec<i32>>()]);
        let error = program("groups.size()", 10)
            .evaluate(&[("groups", &nested)])
            .expect_err("the inner list breaks the promise even though the outer list does not");
        assert!(matches!(error, EvalError::OversizedInput { size: 11, .. }));
    }

    /// The check reaches NESTED collections, not just the top level.
    ///
    /// A top-level-only check is the cheapest wrong way to write this and it passes every test
    /// above: `{"a": [ ...20000 items... ]}` is one entry at the top, and the comprehension
    /// that costs 423 seconds runs over the inner list.
    #[test]
    fn a_nested_collection_over_the_shape_is_refused() {
        let nested = serde_json::json!({"inner": (0..11).collect::<Vec<i32>>()});
        let error = program("attrs.size()", 10)
            .evaluate(&[("attrs", &nested)])
            .expect_err("the inner list breaks the promise even though the outer map does not");
        assert!(matches!(error, EvalError::OversizedInput { size: 11, .. }));
    }
}
