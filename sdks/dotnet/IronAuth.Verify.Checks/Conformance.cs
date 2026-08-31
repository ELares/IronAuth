// SPDX-License-Identifier: MIT OR Apache-2.0
using System.Text.Json;
using IronAuth.Verify;

namespace IronAuth.Verify.Checks;

/// <summary>
/// The .NET verifier against the cross-language conformance corpus (issue #118).
/// </summary>
/// <remarks>
/// <para>
/// The corpus is judged by verifiers in five languages. Most have a capability gap: the Rust
/// verifier has no P-256 key type and refuses the ES256 vector on the allow-list rather than
/// verifying it. .NET does all three algorithms (RSA and P-256 from the platform, Ed25519 through
/// BouncyCastle), so like the Java artifact it verifies EVERY accepted vector, and
/// <c>alg_not_published_by_the_issuer</c> tests what it was written to test.
/// </para>
/// <para>
/// That vector is the SAME token as <c>valid_es256</c>, judged against an issuer publishing EdDSA
/// only. For a verifier that cannot do ES256 at all, passing it proves nothing: it would refuse
/// that token whatever the allow-list said. Here the two differ in exactly one respect and the
/// outcomes differ with them.
/// </para>
/// <para>
/// The reason mapping IS the interoperability contract. The implementations do not share an error
/// vocabulary: the TypeScript core reports eight coarse reasons, this one reports fifteen. The
/// mapping is MANY-TO-ONE and explicit, so a refusal that is right for a more precise reason
/// passes and a refusal for the WRONG reason does not.
/// </para>
/// </remarks>
internal static class Conformance
{
    internal static int Run(string corpusPath)
    {
        using JsonDocument corpus = JsonDocument.Parse(File.ReadAllText(corpusPath));
        JsonElement root = corpus.RootElement;

        long now = root.GetProperty("now").GetInt64();
        string issuer = root.GetProperty("issuer").GetString()!;
        string audience = root.GetProperty("audience").GetString()!;
        IReadOnlyList<TrustedKey> keys = TrustedKey.FromJwks(root.GetProperty("jwks").GetRawText());
        string[] published = [.. root.GetProperty("algorithms").EnumerateArray().Select(a => a.GetString()!)];
        string[] eddsaOnly = [.. root.GetProperty("algorithmsEddsaOnly").EnumerateArray().Select(a => a.GetString()!)];

        List<string> failures = [];
        SortedSet<string> acceptedAlgorithms = [];
        int accepts = 0;
        int refusals = 0;
        int cases = 0;
        HashSet<string> expectations = [];

        foreach (JsonElement vector in root.GetProperty("cases").EnumerateArray())
        {
            cases++;
            string name = vector.GetProperty("name").GetString()!;
            string token = vector.GetProperty("token").GetString()!;
            string expect = vector.GetProperty("expect").GetString()!;
            string why = vector.GetProperty("why").GetString()!;

            // The allow-list is the ISSUER's published set. One vector is judged against an
            // EdDSA-only issuer, which is what turns it into a test of the allow-list rather than
            // of whether ES256 happens to be implemented.
            string[] algorithms = name == "alg_not_published_by_the_issuer" ? eddsaOnly : published;
            IronAuthVerifier verifier = new(algorithms, keys, issuer, audience, 0);

            if (expect == "accept")
            {
                accepts++;
                try
                {
                    JsonElement claims = verifier.Verify(token, now);
                    if (claims.GetProperty("iss").GetString() != issuer)
                    {
                        failures.Add($"{name}: verified but returned a different iss");
                    }
                    acceptedAlgorithms.Add(AlgorithmOf(token));
                }
                catch (VerifyException refused)
                {
                    failures.Add($"{name} must verify ({why}), refused as {refused.Reason}");
                }
                continue;
            }

            refusals++;
            expectations.Add(expect);
            try
            {
                verifier.Verify(token, now);
                failures.Add($"{name} must be refused as {expect} ({why}), but it verified");
            }
            catch (VerifyException refused)
            {
                IReadOnlySet<RejectReason> permitted = Acceptable(name, expect);
                if (permitted.Count == 0)
                {
                    failures.Add($"the corpus expects `{expect}`, which this mapping does not cover");
                }
                else if (!permitted.Contains(refused.Reason))
                {
                    failures.Add($"{name}: the corpus expects `{expect}` and .NET refused it as {refused.Reason}, "
                        + $"which is not among [{string.Join(", ", permitted)}]. {why}");
                }
            }
        }

        // A conformance suite that iterates a list is exactly as good as the list, and the corpus
        // is the artifact someone weakens under deadline. These floors are not style: deleting the
        // alg_none vector would otherwise turn every verifier green on an unsigned token.
        if (cases < 16)
        {
            failures.Add($"the corpus shrank to {cases} vectors");
        }
        if (refusals < 10)
        {
            failures.Add($"only {refusals} refusal vectors reached the verifier");
        }
        if (accepts < 3)
        {
            failures.Add($"only {accepts} accepted vectors, so a refuse-everything verifier would pass");
        }
        // The claim this artifact makes: all three algorithms actually verified. Without this a
        // change that broke RSA would leave the suite green on Ed25519.
        foreach (string required in new[] { "EdDSA", "ES256", "RS256" })
        {
            if (!acceptedAlgorithms.Contains(required))
            {
                failures.Add($"no accepted vector was verified with {required}; this run proves "
                    + $"[{string.Join(", ", acceptedAlgorithms)}]");
            }
        }
        // Checked against the CORPUS rather than against this file, so a new expectation fails
        // here instead of being silently mapped to something adjacent.
        foreach (string required in new[]
        {
            "algorithm_not_allowed", "bad_signature", "unknown_key", "wrong_issuer",
            "wrong_audience", "expired", "not_yet_valid", "malformed",
        })
        {
            if (!expectations.Contains(required))
            {
                failures.Add($"the corpus no longer covers {required}");
            }
        }

        if (failures.Count > 0)
        {
            Console.Error.WriteLine("FAIL: the .NET verifier disagrees with the corpus");
            failures.ForEach(failure => Console.Error.WriteLine("  - " + failure));
            return 1;
        }
        Console.WriteLine($"dotnet conformance: {cases} vectors ({accepts} accepted across "
            + $"[{string.Join(", ", acceptedAlgorithms)}], {refusals} refused) OK");
        return 0;
    }

    /// <summary>The verifier reasons that satisfy one corpus expectation.</summary>
    /// <remarks>
    /// Returns an empty set for an expectation the mapping does not know, which the caller reports
    /// as a failure rather than treating as "nothing to check".
    /// </remarks>
    private static IReadOnlySet<RejectReason> Acceptable(string name, string expect)
    {
        // ONE per-vector widening, named and scoped.
        //
        // The corpus expects `bad_signature` for the embedded-JWK injection, because the
        // TypeScript core resolves the key from the published set, ignores the header's `jwk`, and
        // the attacker's signature then fails against the real key. This verifier refuses it
        // STRUCTURALLY, before any signature is checked. That refusal is strictly stronger: it
        // holds even against a signature that WOULD have validated. Widening `bad_signature`
        // everywhere would let a key-injection refusal satisfy a tampered-payload expectation, so
        // the widening lives here, on the one vector it describes.
        if (name == "embedded_jwk_key_injection")
        {
            return new HashSet<RejectReason> { RejectReason.EmbeddedKeyInjection, RejectReason.SignatureInvalid };
        }
        return expect switch
        {
            "malformed" => new HashSet<RejectReason>
            {
                RejectReason.MalformedStructure,
                RejectReason.Base64Malformed,
                RejectReason.HeaderMalformed,
                RejectReason.ClaimsMalformed,
                RejectReason.UnknownCrit,
            },
            // `alg: none` has its own reason here, which is more precise than the corpus's coarse
            // name and is the same refusal.
            "algorithm_not_allowed" => new HashSet<RejectReason>
            {
                RejectReason.AlgNone, RejectReason.AlgNotAllowed, RejectReason.KeyTypeMismatch,
            },
            "unknown_key" => new HashSet<RejectReason> { RejectReason.UnknownKid },
            "bad_signature" => new HashSet<RejectReason> { RejectReason.SignatureInvalid },
            "wrong_issuer" => new HashSet<RejectReason> { RejectReason.IssuerMismatch },
            "wrong_audience" => new HashSet<RejectReason> { RejectReason.AudienceMismatch },
            "expired" => new HashSet<RejectReason> { RejectReason.Expired },
            "not_yet_valid" => new HashSet<RejectReason> { RejectReason.NotYetValid },
            _ => new HashSet<RejectReason>(),
        };
    }

    /// <summary>The <c>alg</c> a token names, for reporting which algorithms actually verified.</summary>
    private static string AlgorithmOf(string token)
    {
        using JsonDocument header = JsonDocument.Parse(Base64Url.Decode(token.Split('.')[0]));
        return header.RootElement.GetProperty("alg").GetString()!;
    }
}
