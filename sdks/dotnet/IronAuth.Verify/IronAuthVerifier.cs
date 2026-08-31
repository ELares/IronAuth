// SPDX-License-Identifier: MIT OR Apache-2.0
using System.Text;
using System.Text.Json;

namespace IronAuth.Verify;

/// <summary>Why a token was refused.</summary>
public enum RejectReason
{
    /// <summary>Not three dot-separated segments, or over the size cap.</summary>
    MalformedStructure,

    /// <summary>A segment is not unpadded base64url.</summary>
    Base64Malformed,

    /// <summary>The header is not a JSON object, or <c>alg</c> is missing or not a string.</summary>
    HeaderMalformed,

    /// <summary>The header names a <c>crit</c> extension this verifier does not implement.</summary>
    UnknownCrit,

    /// <summary>The header carries or points at its own key, which no honest token needs.</summary>
    EmbeddedKeyInjection,

    /// <summary><c>alg: none</c>: an unsigned token, refused by name.</summary>
    AlgNone,

    /// <summary>The algorithm is not on the caller's allow-list.</summary>
    AlgNotAllowed,

    /// <summary>No trusted key matches the header's <c>kid</c>.</summary>
    UnknownKid,

    /// <summary>A key matched, but cannot carry this algorithm.</summary>
    KeyTypeMismatch,

    /// <summary>The signature does not verify under the resolved key.</summary>
    SignatureInvalid,

    /// <summary>The claims are not a JSON object, or a time claim is missing or not a number.</summary>
    ClaimsMalformed,

    /// <summary><c>iss</c> is absent or is not exactly the expected issuer.</summary>
    IssuerMismatch,

    /// <summary>The expected audience is not among <c>aud</c>.</summary>
    AudienceMismatch,

    /// <summary><c>exp</c> has passed.</summary>
    Expired,

    /// <summary><c>nbf</c> has not arrived.</summary>
    NotYetValid,
}

/// <summary>Thrown for every refusal, carrying the machine-readable reason.</summary>
/// <remarks>
/// The standard parameterless and message-only constructors are deliberately absent. This
/// exception exists to carry a <see cref="RejectReason"/>, and a constructor that leaves it at
/// whatever the enum's zero happens to be would produce an exception claiming a refusal that did
/// not occur. A caller switching on <c>Reason</c> would then take a branch nothing chose.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Design",
    "CA1032:Implement standard exception constructors",
    Justification = "A refusal without a reason is not a refusal this type can represent; see the remarks.")]
public sealed class VerifyException : Exception
{
    /// <param name="reason">the machine-readable refusal</param>
    /// <param name="detail">what specifically was wrong</param>
    public VerifyException(RejectReason reason, string detail) : base($"{reason}: {detail}") => Reason = reason;

    /// <summary>Why the token was refused.</summary>
    public RejectReason Reason { get; }
}

/// <summary>
/// Verify an IronAuth JWT on .NET (issue #118, criterion 5).
/// </summary>
/// <remarks>
/// <para>
/// One dependency, and the criterion named it: BouncyCastle, for Ed25519 alone. .NET has no in-box
/// Ed25519 as of .NET 10, checked rather than assumed. RSA and P-256 come from the platform.
/// </para>
/// <para>
/// The checks run cheapest-and-most-fundamental first, and every one is a refusal someone has
/// shipped a verifier without: three base64url segments within the size cap; a header that parses,
/// names no unrecognised <c>crit</c>, and embeds no key; an <c>alg</c> on the allow-list the
/// CALLER supplied; a key resolved by <c>kid</c>; a valid signature; and only then the claims.
/// </para>
/// <para>
/// <b>The allow-list is the issuer's published metadata, never the token's header.</b> That single
/// rule is what defeats <c>alg: none</c> and the HS256-forged-with-the-public-key attack, and it
/// is why <c>algorithms</c> is a required constructor argument with no default. Claims are read
/// AFTER the signature, so an unsigned token never influences a decision, not even an error
/// message.
/// </para>
/// <para>
/// It does not fetch JWKS, cache keys, or handle rotation: it takes keys the caller resolved. It
/// does not enforce <c>typ</c>, because the shared conformance corpus is run by six verifiers in
/// five languages and mints ordinary <c>typ: JWT</c> tokens; IronAuth deployments pin their media
/// type in the layer above. Both are stated rather than left to be inferred from missing code.
/// </para>
/// </remarks>
public sealed class IronAuthVerifier
{
    /// <summary>
    /// The largest token this verifier will look at.
    /// </summary>
    /// <remarks>
    /// Decoding unbounded attacker input before any check is a denial of service, and "the caller
    /// will have limited it" is how that ends up nobody's job. An IronAuth access token with RSA
    /// is around 700 bytes; 8 KiB is far above anything legitimate.
    /// </remarks>
    public const int MaxTokenBytes = 8192;

    private readonly HashSet<string> _algorithms;
    private readonly IReadOnlyList<TrustedKey> _keys;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly long _skewSeconds;

    /// <param name="algorithms">the algorithms the ISSUER publishes; never read from a token</param>
    /// <param name="keys">the issuer's published keys</param>
    /// <param name="issuer">the exact expected <c>iss</c></param>
    /// <param name="audience">the expected <c>aud</c></param>
    /// <param name="skewSeconds">clock skew allowed on <c>exp</c> and <c>nbf</c></param>
    public IronAuthVerifier(
        IEnumerable<string> algorithms,
        IReadOnlyList<TrustedKey> keys,
        string issuer,
        string audience,
        long skewSeconds)
    {
        ArgumentNullException.ThrowIfNull(algorithms);
        _algorithms = [.. algorithms];
        if (_algorithms.Count == 0)
        {
            // An empty allow-list is almost always a config bug that reads as "allow nothing" and
            // behaves as a silent outage; a caller that means it can pass a real set of one.
            throw new ArgumentException("an algorithm allow-list is required and must not be empty", nameof(algorithms));
        }
        ArgumentOutOfRangeException.ThrowIfNegative(skewSeconds);
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        _audience = audience ?? throw new ArgumentNullException(nameof(audience));
        _skewSeconds = skewSeconds;
    }

    /// <summary>Verify <paramref name="token"/> as at <paramref name="nowEpochSeconds"/>.</summary>
    /// <remarks>
    /// The instant is a parameter rather than a call to the system clock so a caller can test
    /// expiry deterministically. Production callers pass
    /// <c>DateTimeOffset.UtcNow.ToUnixTimeSeconds()</c>.
    /// </remarks>
    /// <returns>the verified claims</returns>
    /// <exception cref="VerifyException">on any refusal, carrying a <see cref="RejectReason"/></exception>
    public JsonElement Verify(string token, long nowEpochSeconds)
    {
        if (token is null || token.Length > MaxTokenBytes)
        {
            throw new VerifyException(RejectReason.MalformedStructure, $"absent or larger than {MaxTokenBytes}");
        }
        // Empty trailing segments are KEPT: `h.p.` must be seen as three segments with an empty
        // signature, which is exactly the `alg: none` shape, not as two.
        string[] segments = token.Split('.');
        if (segments.Length != 3)
        {
            throw new VerifyException(RejectReason.MalformedStructure, $"a JWS has three segments, found {segments.Length}");
        }

        JsonElement header = ReadObject(Decode(segments[0]), RejectReason.HeaderMalformed, "header");

        if (header.TryGetProperty("crit", out _))
        {
            // RFC 7515 4.1.11: an extension a verifier does not understand must be REFUSED, not
            // ignored, because its whole purpose is to change how the token is read. This verifier
            // implements no extensions, so any `crit` at all is unknown.
            throw new VerifyException(RejectReason.UnknownCrit, "the header names a crit extension this verifier does not implement");
        }
        foreach (string carrier in new[] { "jwk", "jku", "x5u", "x5c" })
        {
            if (header.TryGetProperty(carrier, out _))
            {
                // A token that carries or points at its own key is asking to be verified against
                // the attacker's key. Refused STRUCTURALLY, before any signature is checked, so it
                // stays refused even against a signature that would have validated.
                throw new VerifyException(RejectReason.EmbeddedKeyInjection, $"the header carries `{carrier}`");
            }
        }
        if (!header.TryGetProperty("alg", out JsonElement algElement) || algElement.ValueKind != JsonValueKind.String)
        {
            throw new VerifyException(RejectReason.HeaderMalformed, "the header has no `alg` string");
        }
        string alg = algElement.GetString()!;
        if (alg == "none")
        {
            throw new VerifyException(RejectReason.AlgNone, "an unsigned token never verifies");
        }
        if (!_algorithms.Contains(alg))
        {
            throw new VerifyException(RejectReason.AlgNotAllowed, $"{alg} is not published by this issuer");
        }

        string? kid = header.TryGetProperty("kid", out JsonElement kidElement) && kidElement.ValueKind == JsonValueKind.String
            ? kidElement.GetString()
            : null;
        TrustedKey key = Resolve(kid, alg);

        byte[] signature = Decode(segments[2]);
        byte[] signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{segments[1]}");
        if (!SignatureVerifies(key, signingInput, signature))
        {
            throw new VerifyException(RejectReason.SignatureInvalid, $"the signature does not verify under {key}");
        }

        // Everything below here reads a token whose signature has been checked. Nothing above may
        // move below, and nothing below may move above.
        JsonElement claims = ReadObject(Decode(segments[1]), RejectReason.ClaimsMalformed, "claims");

        // Compared EXACTLY: two environments of one deployment differ only by a path segment, so a
        // prefix comparison lets a sibling environment's token in.
        if (!claims.TryGetProperty("iss", out JsonElement iss) || iss.ValueKind != JsonValueKind.String || iss.GetString() != _issuer)
        {
            throw new VerifyException(RejectReason.IssuerMismatch, $"iss is not {_issuer}");
        }
        if (!AudienceMatches(claims))
        {
            throw new VerifyException(RejectReason.AudienceMismatch, $"aud does not include {_audience}");
        }
        // A token with no expiry is a token that never expires. Refused rather than shrugged at.
        if (!TryTime(claims, "exp", out long exp))
        {
            throw new VerifyException(RejectReason.ClaimsMalformed, "exp is absent or not a number");
        }
        if (nowEpochSeconds > exp + _skewSeconds)
        {
            throw new VerifyException(RejectReason.Expired, $"exp passed at {exp}");
        }
        if (claims.TryGetProperty("nbf", out _))
        {
            // Present but not a number is MALFORMED, not absent. Treating it as absent would mean
            // `"nbf": "tomorrow"` silently disables the check it was written to perform.
            if (!TryTime(claims, "nbf", out long nbf))
            {
                throw new VerifyException(RejectReason.ClaimsMalformed, "nbf is present but not a number");
            }
            if (nowEpochSeconds < nbf - _skewSeconds)
            {
                throw new VerifyException(RejectReason.NotYetValid, $"nbf arrives at {nbf}");
            }
        }
        return claims;
    }

    /// <summary>
    /// Find the trusted key named by <paramref name="kid"/> that can carry <paramref name="alg"/>.
    /// </summary>
    /// <remarks>
    /// An absent <c>kid</c> is allowed only when exactly one trusted key fits the algorithm. With
    /// several, guessing would mean trying each in turn, which quietly converts "the issuer
    /// rotated" into "any published key will do".
    /// </remarks>
    private TrustedKey Resolve(string? kid, string alg)
    {
        List<TrustedKey> named = kid is null ? [.. _keys] : [.. _keys.Where(candidate => candidate.Kid == kid)];
        if (named.Count == 0)
        {
            throw new VerifyException(RejectReason.UnknownKid, $"no published key has kid {kid}");
        }
        List<TrustedKey> usable = [.. named.Where(candidate => candidate.Supports(alg))];
        if (usable.Count == 0)
        {
            throw new VerifyException(RejectReason.KeyTypeMismatch, $"the key named {kid} cannot carry {alg}");
        }
        if (usable.Count > 1)
        {
            throw new VerifyException(RejectReason.UnknownKid, $"several published keys match kid {kid}");
        }
        return usable[0];
    }

    private static bool SignatureVerifies(TrustedKey key, byte[] signingInput, byte[] signature)
    {
        try
        {
            return key.Verify(signingInput, signature);
        }
        catch (Exception refused) when (refused is not VerifyException)
        {
            // A malformed signature makes the provider throw rather than return false (an ECDSA
            // pair of the wrong length, for one). That is a failed verification, not a crash, and
            // it must not escape as an exception the caller never declared.
            return false;
        }
    }

    private bool AudienceMatches(JsonElement claims)
    {
        if (!claims.TryGetProperty("aud", out JsonElement aud))
        {
            return false;
        }
        if (aud.ValueKind == JsonValueKind.String)
        {
            return aud.GetString() == _audience;
        }
        if (aud.ValueKind == JsonValueKind.Array)
        {
            // RFC 7519 4.1.3: aud may be an array, and MEMBERSHIP is what counts. Not the first
            // element, and not the whole array rendered as a string.
            return aud.EnumerateArray().Any(entry => entry.ValueKind == JsonValueKind.String && entry.GetString() == _audience);
        }
        return false;
    }

    private static bool TryTime(JsonElement claims, string name, out long seconds)
    {
        seconds = 0;
        return claims.TryGetProperty(name, out JsonElement value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt64(out seconds);
    }

    private static byte[] Decode(string segment)
    {
        try
        {
            return Base64Url.Decode(segment);
        }
        catch (FormatException)
        {
            throw new VerifyException(RejectReason.Base64Malformed, "a segment is not unpadded base64url");
        }
    }

    private static JsonElement ReadObject(byte[] bytes, RejectReason reason, string what)
    {
        try
        {
            // A depth cap, because the parser is recursive and attacker input decides the nesting.
            // System.Text.Json defaults to 64; naming it here makes the bound a decision rather
            // than a default someone can change out from under this file.
            JsonDocumentOptions options = new() { MaxDepth = 32 };
            using JsonDocument document = JsonDocument.Parse(bytes, options);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new VerifyException(reason, $"the {what} is not a JSON object");
            }
            // Cloned because the JsonDocument is disposed on leaving this scope, and a JsonElement
            // pointing into a disposed document throws later, far from here.
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new VerifyException(reason, $"the {what} is not JSON");
        }
    }
}
