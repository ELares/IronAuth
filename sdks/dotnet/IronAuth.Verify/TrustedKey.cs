// SPDX-License-Identifier: MIT OR Apache-2.0
using System.Security.Cryptography;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace IronAuth.Verify;

/// <summary>
/// One public key published by an IronAuth issuer, decoded from its JWK (issue #118).
/// </summary>
/// <remarks>
/// <para>
/// Subclassed per key type rather than holding a loosely typed key object, so "can this key carry
/// this algorithm" is answered by the type system instead of by a cast that might throw at the
/// worst moment.
/// </para>
/// <para>
/// RSA and P-256 come from <c>System.Security.Cryptography</c>. Ed25519 does not: .NET has no
/// in-box Ed25519 as of .NET 10, which is why this artifact carries the one BouncyCastle
/// dependency the criterion anticipated.
/// </para>
/// </remarks>
public abstract class TrustedKey : IDisposable
{
    /// <summary>The JWK key id, or null for a key published without one.</summary>
    public string? Kid { get; }

    /// <summary>The JWK key type, used to refuse a key that cannot carry an algorithm.</summary>
    public abstract string Kty { get; }

    /// <param name="kid">the key id from the JWK, if it published one</param>
    protected TrustedKey(string? kid) => Kid = kid;

    /// <summary>Whether this key can carry a signature made with <paramref name="alg"/>.</summary>
    public abstract bool Supports(string alg);

    /// <summary>Whether <paramref name="signature"/> is valid over <paramref name="signingInput"/>.</summary>
    public abstract bool Verify(ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature);

    /// <summary>
    /// Deliberately not the key material. A public key is not a secret, but a verifier that
    /// prints key bytes into logs trains people to paste them around.
    /// </summary>
    public override string ToString() => $"TrustedKey[kid={Kid}, kty={Kty}]";

    /// <summary>Release the platform key handles this key holds.</summary>
    /// <remarks>
    /// <para>
    /// The RSA and P-256 subclasses wrap <see cref="System.Security.Cryptography.RSA"/> and
    /// <see cref="System.Security.Cryptography.ECDsa"/>, which own native handles. A verifier
    /// built once at startup would never notice, but a deployment refetching JWKS on a rotation
    /// schedule builds a new key set every time and would accumulate handles until a collection
    /// happened to run.
    /// </para>
    /// <para>
    /// Ed25519 keys hold only managed BouncyCastle state and have nothing to release; they
    /// implement this because the caller cannot tell the subclasses apart and should not have to.
    /// </para>
    /// </remarks>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <param name="disposing">true when called from <see cref="Dispose()"/> rather than a finalizer</param>
    protected virtual void Dispose(bool disposing)
    {
        // Nothing by default: an Ed25519 key holds no unmanaged resource.
    }

    /// <summary>Decode a JWK Set document into the keys this verifier can represent.</summary>
    /// <remarks>
    /// A key type this build cannot represent is SKIPPED rather than fatal: an issuer may publish
    /// a key for an algorithm this verifier does not accept, and refusing to start would make the
    /// whole key set unusable over one unrelated entry. A token naming that key then gets
    /// <see cref="RejectReason.UnknownKid"/>, which is the right answer: this verifier really does
    /// not know that key.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each decoded key transfers to the returned list, which the caller disposes; a failure partway through disposes what was already built.")]
    public static IReadOnlyList<TrustedKey> FromJwks(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("keys", out JsonElement keys) || keys.ValueKind != JsonValueKind.Array)
        {
            throw new ArgumentException("a JWK Set has a `keys` array", nameof(json));
        }

        List<TrustedKey> decoded = [];
        try
        {
            foreach (JsonElement jwk in keys.EnumerateArray())
            {
                TrustedKey? key = TryDecode(jwk);
                if (key is not null)
                {
                    decoded.Add(key);
                }
            }
        }
        catch
        {
            // A failure partway through would otherwise strand the keys already built, each
            // holding a platform handle. TryDecode swallows the malformed-key cases itself, so
            // reaching here means something unanticipated, which is exactly when a leak is
            // least likely to be noticed.
            decoded.ForEach(built => built.Dispose());
            throw;
        }
        // Ownership passes to the caller with the list; see the Dispose remarks on this type.
        return decoded;
    }

    private static TrustedKey? TryDecode(JsonElement jwk)
    {
        string? kid = Text(jwk, "kid");
        string? kty = Text(jwk, "kty");
        try
        {
            switch (kty)
            {
                case "OKP" when Text(jwk, "crv") == "Ed25519":
                    return new Ed25519Key(kid, Base64Url.Decode(Required(jwk, "x")));
                case "EC" when Text(jwk, "crv") == "P-256":
                    return new P256Key(kid, Base64Url.Decode(Required(jwk, "x")), Base64Url.Decode(Required(jwk, "y")));
                case "RSA":
                    return new RsaKey(kid, Base64Url.Decode(Required(jwk, "n")), Base64Url.Decode(Required(jwk, "e")));
                default:
                    return null;
            }
        }
        catch (Exception malformed) when (malformed is ArgumentException or FormatException or CryptographicException)
        {
            // A key that does not decode is not a trusted key. Same reasoning as above: one bad
            // entry must not deny the others.
            return null;
        }
    }

    private static string? Text(JsonElement jwk, string member) =>
        jwk.TryGetProperty(member, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string Required(JsonElement jwk, string member) =>
        Text(jwk, member) ?? throw new ArgumentException($"the JWK has no `{member}`", nameof(jwk));
}

/// <summary>An Ed25519 key, verified through BouncyCastle.</summary>
internal sealed class Ed25519Key : TrustedKey
{
    private readonly Ed25519PublicKeyParameters _key;

    /// <remarks>
    /// BouncyCastle takes RFC 8032's raw 32-byte encoding directly, so unlike the JDK there is no
    /// parity bit to lift out of the y coordinate here.
    /// </remarks>
    internal Ed25519Key(string? kid, byte[] x) : base(kid) => _key = new Ed25519PublicKeyParameters(x, 0);

    public override string Kty => "OKP";

    public override bool Supports(string alg) => alg == "EdDSA";

    public override bool Verify(ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        Ed25519Signer signer = new();
        signer.Init(false, _key);
        signer.BlockUpdate(signingInput.ToArray(), 0, signingInput.Length);
        return signer.VerifySignature(signature.ToArray());
    }
}

/// <summary>A P-256 key, verified by the platform.</summary>
internal sealed class P256Key : TrustedKey
{
    private readonly ECDsa _key;

    internal P256Key(string? kid, byte[] x, byte[] y) : base(kid) =>
        _key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x, Y = y },
        });

    public override string Kty => "EC";

    public override bool Supports(string alg) => alg == "ES256";

    /// <remarks>
    /// .NET's <see cref="ECDsa.VerifyData(byte[], byte[], HashAlgorithmName)"/> takes the raw
    /// r||s pair by default, which is exactly what JWS carries. No DER conversion, and so none of
    /// the parser bugs that conversion classically brings with it.
    /// </remarks>
    public override bool Verify(ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature) =>
        _key.VerifyData(signingInput, signature, HashAlgorithmName.SHA256);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Dispose();
        }
        base.Dispose(disposing);
    }
}

/// <summary>An RSA key, verified by the platform.</summary>
internal sealed class RsaKey : TrustedKey
{
    private readonly RSA _key;

    internal RsaKey(string? kid, byte[] modulus, byte[] exponent) : base(kid) =>
        _key = RSA.Create(new RSAParameters { Modulus = modulus, Exponent = exponent });

    public override string Kty => "RSA";

    public override bool Supports(string alg) => alg == "RS256";

    public override bool Verify(ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature) =>
        _key.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Dispose();
        }
        base.Dispose(disposing);
    }
}
