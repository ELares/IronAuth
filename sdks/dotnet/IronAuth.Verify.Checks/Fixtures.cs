// SPDX-License-Identifier: MIT OR Apache-2.0
using System.Text;
using IronAuth.Verify;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace IronAuth.Verify.Checks;

/// <summary>
/// Minting helpers shared by the self-test and the sample harness (issue #118).
/// </summary>
/// <remarks>
/// These exist because both suites need to sign a token the shared corpus could not contain: the
/// corpus carries no private key, so anything requiring a VALID signature over an attacker-chosen
/// header has to be minted here.
/// </remarks>
internal static class Fixtures
{
    /// <summary>Generate a fresh Ed25519 key pair.</summary>
    internal static AsymmetricCipherKeyPair GenerateEd25519()
    {
        Ed25519KeyPairGenerator generator = new();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return generator.GenerateKeyPair();
    }

    /// <summary>Mint a genuinely signed Ed25519 JWS over the given header and claims, verbatim.</summary>
    internal static string Mint(AsymmetricCipherKeyPair pair, string header, string claims)
    {
        string signingInput = Base64Url.Encode(Encoding.UTF8.GetBytes(header))
            + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(claims));
        byte[] bytes = Encoding.ASCII.GetBytes(signingInput);
        Ed25519Signer signer = new();
        signer.Init(true, pair.Private);
        signer.BlockUpdate(bytes, 0, bytes.Length);
        return signingInput + "." + Base64Url.Encode(signer.GenerateSignature());
    }

    /// <summary>The raw 32-byte public key, which is exactly what a JWK's <c>x</c> carries.</summary>
    internal static string PublicX(AsymmetricCipherKeyPair pair) =>
        Base64Url.Encode(((Ed25519PublicKeyParameters)pair.Public).GetEncoded());
}
