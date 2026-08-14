// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The generated corpus module is plain data. Typed loosely on purpose: the SHAPE is
// asserted at runtime by `the generated vectors module matches the json corpus`, which
// compares it to the canonical JSON, and a hand-written interface here would be a second
// declaration of that shape to keep in step for no checking gain.
declare const corpus: {
  readonly issuer: string;
  readonly audience: string;
  readonly now: number;
  readonly algorithms: readonly string[];
  readonly algorithmsEddsaOnly: readonly string[];
  readonly jwks: unknown;
  readonly cases: readonly { name: string; token: string; expect: string; why: string }[];
};
export default corpus;
