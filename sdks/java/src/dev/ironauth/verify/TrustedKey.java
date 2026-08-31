// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * One public key published by an IronAuth issuer, decoded from its JWK (issue #118).
 *
 * <p>The JDK can do all three of IronAuth's signing algorithms with no third-party library:
 * Ed25519 arrived in Java 15 (JEP 339), and RSA and P-256 have been there far longer. So this
 * artifact bundles no crypto provider at all, which is a stronger version of the "no extra user
 * dependencies" promise than bundling one would be.
 *
 * @param kid the JWK's key id, or {@code null} for a key published without one
 * @param kty the JWK key type, retained so the verifier can refuse a key of the wrong type for
 *     an algorithm rather than handing it to a {@code Signature} that would throw
 * @param key the decoded public key
 */
public record TrustedKey(String kid, String kty, PublicKey key) {

    /** Decode a JWK Set document into the keys this verifier can represent. */
    public static List<TrustedKey> fromJwks(String json) {
        Object parsed = Json.parse(json);
        if (!(parsed instanceof Map<?, ?> document)) {
            throw new IllegalArgumentException("a JWK Set is a JSON object");
        }
        if (!(document.get("keys") instanceof List<?> entries)) {
            throw new IllegalArgumentException("a JWK Set has a `keys` array");
        }
        List<TrustedKey> keys = new ArrayList<>();
        for (Object entry : entries) {
            if (entry instanceof Map<?, ?> jwk) {
                // A key type this build cannot represent is SKIPPED rather than fatal: an issuer
                // may publish a key for an algorithm this verifier does not accept, and refusing
                // to start would make the whole key set unusable over one unrelated entry. The
                // consequence is a token naming that key gets `UNKNOWN_KID`, which is the right
                // answer -- this verifier really does not know that key.
                TrustedKey decoded = fromJwk(jwk);
                if (decoded != null) {
                    keys.add(decoded);
                }
            }
        }
        return List.copyOf(keys);
    }

    private static TrustedKey fromJwk(Map<?, ?> jwk) {
        String kid = jwk.get("kid") instanceof String value ? value : null;
        if (!(jwk.get("kty") instanceof String kty)) {
            return null;
        }
        try {
            switch (kty) {
                case "OKP": {
                    if (!"Ed25519".equals(jwk.get("crv"))) {
                        return null;
                    }
                    return new TrustedKey(kid, kty, ed25519(text(jwk, "x")));
                }
                case "EC": {
                    if (!"P-256".equals(jwk.get("crv"))) {
                        return null;
                    }
                    return new TrustedKey(kid, kty, p256(text(jwk, "x"), text(jwk, "y")));
                }
                case "RSA":
                    return new TrustedKey(kid, kty, rsa(text(jwk, "n"), text(jwk, "e")));
                default:
                    return null;
            }
        } catch (Exception malformed) {
            // A key that does not decode is not a trusted key. Same reasoning as above: one bad
            // entry must not deny the others.
            return null;
        }
    }

    private static String text(Map<?, ?> jwk, String member) {
        if (jwk.get(member) instanceof String value) {
            return value;
        }
        throw new IllegalArgumentException("the JWK has no `" + member + "`");
    }

    /**
     * Build an Ed25519 public key from a JWK's raw {@code x}.
     *
     * <p>RFC 8032's encoding is not the (x, y) pair {@link EdECPoint} wants. It is the
     * 32-byte LITTLE-ENDIAN y coordinate with the top bit of the last byte carrying the parity
     * of x, since y alone leaves only two candidates for x and one bit picks between them. So
     * the bit has to be lifted out and cleared before the remainder is read as a number, and
     * the bytes reversed, or the key silently becomes a different point.
     */
    private static PublicKey ed25519(String x) throws Exception {
        byte[] raw = base64Url(x);
        if (raw.length != 32) {
            throw new IllegalArgumentException("an Ed25519 x is 32 bytes, got " + raw.length);
        }
        boolean xOdd = (raw[31] & 0x80) != 0;
        byte[] bigEndian = new byte[32];
        for (int i = 0; i < 32; i++) {
            bigEndian[i] = raw[31 - i];
        }
        bigEndian[0] &= 0x7f; // the parity bit, now at the front, is not part of y
        BigInteger y = new BigInteger(1, bigEndian);
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
    }

    private static PublicKey p256(String x, String y) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new BigInteger(1, base64Url(x)), new BigInteger(1, base64Url(y)));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, curve));
    }

    private static PublicKey rsa(String n, String e) throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(new BigInteger(1, base64Url(n)), new BigInteger(1, base64Url(e))));
    }

    private static byte[] base64Url(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    /** Whether this key can carry a signature made with {@code alg}. */
    boolean supports(String alg) {
        return switch (alg) {
            case "EdDSA" -> "OKP".equals(kty);
            case "ES256" -> "EC".equals(kty);
            case "RS256" -> "RSA".equals(kty);
            default -> false;
        };
    }

    @Override
    public String toString() {
        // Deliberately not the key material. A public key is not a secret, but a verifier that
        // prints key bytes into logs trains people to paste them around.
        return "TrustedKey[kid=" + kid + ", kty=" + kty + "]";
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof TrustedKey that
                && java.util.Objects.equals(kid, that.kid)
                && java.util.Objects.equals(kty, that.kty)
                && java.util.Objects.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(new Object[] {kid, kty, key});
    }
}
