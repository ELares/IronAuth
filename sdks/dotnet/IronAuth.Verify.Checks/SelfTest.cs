// SPDX-License-Identifier: MIT OR Apache-2.0
using System.Globalization;
using System.Text;
using IronAuth.Verify;
using Org.BouncyCastle.Crypto;

namespace IronAuth.Verify.Checks;

/// <summary>
/// The properties the shared corpus CANNOT express (issue #118).
/// </summary>
/// <remarks>
/// <para>
/// The corpus is a fixed list of tokens signed by fixed keys, so every property it can state has
/// the form "this exact token gets this answer". Several things this verifier claims are not of
/// that form, and each was chosen because a mutation run showed the corpus blind to it:
/// </para>
/// <para>
/// Key injection is refused BEFORE the signature is checked. The corpus's
/// <c>embedded_jwk_key_injection</c> vector carries an attacker's key AND an attacker's signature,
/// so a verifier with no structural check still refuses it: the signature fails against the real
/// key. Deleting the check keeps the corpus green. Proving the refusal is structural needs a token
/// whose signature is genuinely VALID, which the corpus has no private key to mint.
/// </para>
/// <para>
/// Size is bounded before decoding; no fixed corpus contains a 9 KiB token. A token with no
/// expiry never verifies; every corpus vector has <c>exp</c>. And no input escapes
/// <c>Verify</c> as an unexpected exception: the corpus's malformed vectors are malformed BASE64,
/// where these are valid base64 carrying hostile JSON, which is a different door.
/// </para>
/// </remarks>
internal static class SelfTest
{
    private const string Issuer = "https://issuer.example/t/tnt_self/e/env_self";
    private const string Audience = "cli_self";
    private const long Now = 1_800_000_000L;

    private static readonly List<string> Failures = [];
    private static int _checked;

    internal static int Run()
    {
        AsymmetricCipherKeyPair pair = Fixtures.GenerateEd25519();
        IReadOnlyList<TrustedKey> keys = TrustedKey.FromJwks(
            $$"""{"keys":[{"kty":"OKP","crv":"Ed25519","x":"{{Fixtures.PublicX(pair)}}","kid":"self-1"}]}""");
        IronAuthVerifier verifier = new(["EdDSA"], keys, Issuer, Audience, 0);

        string claims = string.Create(CultureInfo.InvariantCulture,
            $$"""{"iss":"{{Issuer}}","aud":"{{Audience}}","sub":"usr_self","exp":{{Now + 3600}}}""");

        // THE CONTROL, and the reason the next assertion means anything. It varies from the
        // injection token in exactly ONE respect: the header. Without it, a refusal below could be
        // caused by a mint this test got wrong, and would look identical.
        string honest = Fixtures.Mint(pair, """{"alg":"EdDSA","typ":"JWT","kid":"self-1"}""", claims);
        Accepts(verifier, honest, "a correctly minted token verifies (the control for the next case)");

        // The property the corpus cannot reach: a VALID signature by a PUBLISHED key with a `jwk`
        // header bolted on. A verifier that merely ignores the embedded key accepts this, because
        // the signature really does verify. Only a structural refusal catches it.
        string injected = Fixtures.Mint(
            pair,
            """{"alg":"EdDSA","typ":"JWT","kid":"self-1","jwk":{"kty":"OKP","crv":"Ed25519","x":"F83SEmSVgKMBLYCoZfCPDHVGDGVoXVfyxRZsGnPPYQE"}}""",
            claims);
        Refuses(verifier, injected, RejectReason.EmbeddedKeyInjection,
            "a header carrying its own key is refused even when the signature is VALID");

        // The indirect forms: `jku` and `x5u` point AT a key instead of carrying one, which is the
        // same attack with a fetch in the middle.
        foreach (string member in new[] { """jku":"https://attacker.example/keys""", """x5u":"https://attacker.example/chain""" })
        {
            string header = $$"""{"alg":"EdDSA","typ":"JWT","kid":"self-1","{{member}}"}""";
            Refuses(verifier, Fixtures.Mint(pair, header, claims), RejectReason.EmbeddedKeyInjection,
                "a header pointing AT a key is refused too, not only one carrying it");
        }

        // Bounded before decoding. A validly signed token padded past the cap must still be refused
        // on size, so the bound is not merely documented.
        Refuses(verifier, honest + new string('A', IronAuthVerifier.MaxTokenBytes),
            RejectReason.MalformedStructure, "an oversized token is refused before decoding");

        // Padding is not accepted: one token must have exactly one encoding.
        Refuses(verifier, honest[..honest.LastIndexOf('.')] + ".AA==",
            RejectReason.Base64Malformed, "a PADDED segment is refused, so a token has one encoding");

        // A token with no expiry is a token that never expires.
        Refuses(verifier,
            Fixtures.Mint(pair, """{"alg":"EdDSA","typ":"JWT","kid":"self-1"}""",
                $$"""{"iss":"{{Issuer}}","aud":"{{Audience}}","sub":"usr_self"}"""),
            RejectReason.ClaimsMalformed, "a token with no exp never verifies");

        // `nbf` present but not a number must be MALFORMED, not treated as absent: otherwise
        // `"nbf": "tomorrow"` silently disables the check it was written to perform.
        Refuses(verifier,
            Fixtures.Mint(pair, """{"alg":"EdDSA","typ":"JWT","kid":"self-1"}""",
                string.Create(CultureInfo.InvariantCulture,
                    $$"""{"iss":"{{Issuer}}","aud":"{{Audience}}","exp":{{Now + 3600}},"nbf":"tomorrow"}""")),
            RejectReason.ClaimsMalformed, "a non-numeric nbf is malformed, not absent");

        // NO INPUT ESCAPES Verify AS AN UNEXPECTED EXCEPTION.
        //
        // Verify documents VerifyException, so a caller writes one catch and believes it covers
        // every bad token. In the Java sibling artifact, two of these inputs made a hand-written
        // JSON reader throw an unchecked exception that sailed past the verifier's catch: in a
        // web handler that is a 500 where a 401 belonged. .NET uses System.Text.Json rather than a
        // hand-written reader, so this is checking a different thing -- that the JsonException
        // surface really is what the verifier catches, and that the depth cap holds.
        char backslash = (char)92;
        string head = "{\"alg\":\"EdDSA\",\"kid\":\"self-1\",\"x\":\"";
        string[] hostileHeaders =
        [
            head + backslash,
            head + backslash + "u12",
            head + backslash + "uZZZZ" + "\"}",
            head + backslash + "q\"}",
            string.Concat(Enumerable.Repeat("[", 6100)),
            string.Concat(Enumerable.Repeat("""{"a":""", 6100)) + "1",
        ];
        foreach (string hostile in hostileHeaders)
        {
            string token = Base64Url.Encode(Encoding.UTF8.GetBytes(hostile)) + ".e30.AA";
            _checked++;
            try
            {
                verifier.Verify(token, Now);
                Failures.Add("a hostile header VERIFIED: " + Summarise(hostile));
            }
            catch (VerifyException)
            {
                // A refusal is the point; which refusal is not, since these are all garbage.
            }
#pragma warning disable CA1031 // catching everything is the ASSERTION here, not an oversight
            catch (Exception escaped)
#pragma warning restore CA1031
            {
                Failures.Add($"a hostile header threw {escaped.GetType().Name} out of Verify(), "
                    + "which callers do not expect: " + Summarise(hostile));
            }
        }

        // THE CLAIMS DEPTH CAP IS 32, AND THAT NUMBER IS LOAD-BEARING.
        //
        // System.Text.Json already refuses runaway nesting at its own default of 64, so a
        // mutation raising the cap to 10000 SURVIVED every other check here: the 6100-deep header
        // above is refused either way. A bound nothing distinguishes is decoration, and the honest
        // options were to delete it or to measure it.
        //
        // Measured. These claims nest 40 deep: legal JSON, well inside the platform default, and
        // refused by the cap this verifier actually sets. IronAuth tokens are flat, so nothing
        // legitimate is anywhere near this.
        string deepClaims = string.Create(CultureInfo.InvariantCulture,
            $$"""{"iss":"{{Issuer}}","aud":"{{Audience}}","exp":{{Now + 3600}},"deep":""")
            + string.Concat(Enumerable.Repeat("""{"a":""", 40)) + "1" + new string('}', 40) + "}";
        Refuses(verifier, Fixtures.Mint(pair, """{"alg":"EdDSA","typ":"JWT","kid":"self-1"}""", deepClaims),
            RejectReason.ClaimsMalformed, "claims nested past the cap are refused, at 32 rather than the platform default");

        // And the control that keeps the number honest in the other direction: nesting well INSIDE
        // the cap must still verify. Without it, a cap of 1 would pass the assertion above.
        string shallowClaims = string.Create(CultureInfo.InvariantCulture,
            $$"""{"iss":"{{Issuer}}","aud":"{{Audience}}","exp":{{Now + 3600}},"deep":""")
            + string.Concat(Enumerable.Repeat("""{"a":""", 8)) + "1" + new string('}', 8) + "}";
        Accepts(verifier, Fixtures.Mint(pair, """{"alg":"EdDSA","typ":"JWT","kid":"self-1"}""", shallowClaims),
            "claims nested INSIDE the cap still verify (the control for the cap above)");

        // An empty allow-list reads as "allow nothing" and behaves as a silent outage, so it is
        // refused at construction rather than at the first request.
        _checked++;
        try
        {
            _ = new IronAuthVerifier([], keys, Issuer, Audience, 0);
            Failures.Add("an empty algorithm allow-list was accepted at construction");
        }
        catch (ArgumentException)
        {
            // as intended
        }

        // A floor, so commenting assertions out fails here instead of reporting a smaller number
        // in a green run. A floor and not an equality: adding a property should not break it.
        if (_checked < 17)
        {
            Console.Error.WriteLine($"FAIL: only {_checked} properties ran; this suite is its list");
            return 1;
        }
        if (Failures.Count > 0)
        {
            Console.Error.WriteLine("FAIL: the .NET verifier does not hold its own claims");
            Failures.ForEach(failure => Console.Error.WriteLine("  - " + failure));
            return 1;
        }
        Console.WriteLine($"dotnet self-test: {_checked} properties the corpus cannot express OK");
        return 0;
    }

    /// <summary>A short, log-safe rendering of a hostile input, so a failure names it briefly.</summary>
    private static string Summarise(string hostile) =>
        $"({hostile.Length} chars) " + (hostile.Length > 40 ? hostile[..40] + "..." : hostile);

    private static void Accepts(IronAuthVerifier verifier, string token, string why)
    {
        _checked++;
        try
        {
            verifier.Verify(token, Now);
        }
        catch (VerifyException refused)
        {
            Failures.Add($"{why} -- refused as {refused.Reason}");
        }
    }

    private static void Refuses(IronAuthVerifier verifier, string token, RejectReason expected, string why)
    {
        _checked++;
        try
        {
            verifier.Verify(token, Now);
            Failures.Add($"{why} -- but it VERIFIED");
        }
        catch (VerifyException refused)
        {
            if (refused.Reason != expected)
            {
                Failures.Add($"{why} -- expected {expected}, got {refused.Reason}");
            }
        }
    }
}
