// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verify an IronAuth JWT with nothing but the JDK (issue #118, criterion 4).
 *
 * <p>The criterion asked for a Java artifact that verifies an IronAuth Ed25519 token "out of the
 * box... with no extra user dependencies", and expected that to mean bundling Google Tink,
 * because Nimbus JOSE+JWT historically needed Tink for EdDSA. On a modern JDK neither is needed:
 * Java 15 added Ed25519 to the platform (JEP 339). Bundling nothing beats bundling glue, so this
 * artifact has no dependencies at all -- not even a JSON parser, hence {@link Json}.
 *
 * <h2>What this refuses, and why the order matters</h2>
 *
 * <p>The checks run cheapest-and-most-fundamental first, and every one of them is a refusal
 * someone has actually shipped a verifier without:
 *
 * <ol>
 *   <li>the token is three base64url segments and not larger than {@link #MAX_TOKEN_BYTES};
 *   <li>the header parses, carries no unrecognised {@code crit}, and embeds no key;
 *   <li>{@code alg} is on the allow-list <em>the caller</em> supplied;
 *   <li>the key is resolved from the trusted set by {@code kid};
 *   <li>the signature verifies;
 *   <li>and only then are {@code iss}, {@code aud}, {@code exp} and {@code nbf} read.
 * </ol>
 *
 * <p><strong>The allow-list is the issuer's published metadata, never the token's header.</strong>
 * That single rule is what defeats {@code alg: none} and the HS256-forged-with-the-public-key
 * attack, and a verifier that reads {@code alg} to decide what to accept is broken no matter how
 * carefully it does the rest. It is why {@code algorithms} is a required constructor argument
 * with no default.
 *
 * <p>Claims are read <em>after</em> the signature, so an unsigned token can never influence a
 * decision, not even to produce a more specific error message.
 *
 * <h2>What this deliberately does not do</h2>
 *
 * <p>It does not fetch JWKS, cache keys, or handle rotation: it takes keys the caller resolved.
 * It does not enforce {@code typ}, because the shared conformance corpus is run by six verifiers
 * in five languages and mints ordinary {@code typ: JWT} tokens; IronAuth's own deployments pin
 * their media type in the layer above. Both are stated here rather than left for a reader to
 * discover from the absence of code.
 */
public final class IronAuthVerifier {

    /**
     * The largest token this verifier will look at.
     *
     * <p>Base64-decoding unbounded attacker input before any check is a denial-of-service, and
     * "the caller will have limited it" is how that ends up nobody's job. An IronAuth access
     * token with RSA is around 700 bytes; 8 KiB is far above anything legitimate.
     */
    public static final int MAX_TOKEN_BYTES = 8192;

    /** Why a token was refused. */
    public enum Reason {
        /** Not three dot-separated segments, or over {@link #MAX_TOKEN_BYTES}. */
        MALFORMED_STRUCTURE,
        /** A segment is not unpadded base64url. */
        BASE64_MALFORMED,
        /** The header is not a JSON object, or {@code alg} is missing or not a string. */
        HEADER_MALFORMED,
        /** The header names a {@code crit} extension this verifier does not implement. */
        UNKNOWN_CRIT,
        /** The header carries its own key, which no honest token needs. */
        EMBEDDED_KEY_INJECTION,
        /** {@code alg: none}: an unsigned token, refused by name. */
        ALG_NONE,
        /** The algorithm is not on the caller's allow-list. */
        ALG_NOT_ALLOWED,
        /** No trusted key matches the header's {@code kid}. */
        UNKNOWN_KID,
        /** A key matched, but cannot carry this algorithm. */
        KEY_TYPE_MISMATCH,
        /** The signature does not verify under the resolved key. */
        SIGNATURE_INVALID,
        /** The claims are not a JSON object, or {@code exp} is missing or not a number. */
        CLAIMS_MALFORMED,
        /** {@code iss} is absent or is not exactly the expected issuer. */
        ISSUER_MISMATCH,
        /** The expected audience is not among {@code aud}. */
        AUDIENCE_MISMATCH,
        /** {@code exp} has passed. */
        EXPIRED,
        /** {@code nbf} has not arrived. */
        NOT_YET_VALID,
    }

    /** Thrown for every refusal, carrying the machine-readable {@link Reason}. */
    public static final class VerifyException extends Exception {
        private static final long serialVersionUID = 1L;
        private final transient Reason reason;

        VerifyException(Reason reason, String detail) {
            super(reason + ": " + detail);
            this.reason = reason;
        }

        public Reason reason() {
            return reason;
        }
    }

    private final Set<String> algorithms;
    private final List<TrustedKey> keys;
    private final String issuer;
    private final String audience;
    private final long skewSeconds;

    /**
     * @param algorithms the algorithms the ISSUER publishes; required, and never read from a token
     * @param keys the issuer's published keys
     * @param issuer the exact expected {@code iss}
     * @param audience the expected {@code aud}
     * @param skewSeconds clock skew allowed on {@code exp} and {@code nbf}
     */
    public IronAuthVerifier(
            Set<String> algorithms, List<TrustedKey> keys, String issuer, String audience, long skewSeconds) {
        if (algorithms == null || algorithms.isEmpty()) {
            // An empty allow-list is almost always a config bug that reads as "allow nothing" and
            // behaves as a silent outage; a caller that means it can pass a real set of one.
            throw new IllegalArgumentException("an algorithm allow-list is required and must not be empty");
        }
        if (skewSeconds < 0) {
            throw new IllegalArgumentException("skew cannot be negative");
        }
        this.algorithms = Set.copyOf(algorithms);
        this.keys = List.copyOf(keys);
        this.issuer = java.util.Objects.requireNonNull(issuer, "issuer");
        this.audience = java.util.Objects.requireNonNull(audience, "audience");
        this.skewSeconds = skewSeconds;
    }

    /**
     * Verify {@code token} as at {@code nowEpochSeconds}, returning its claims.
     *
     * <p>The instant is a parameter rather than a call to the system clock so that a caller can
     * test expiry deterministically. Production callers pass {@code Instant.now().getEpochSecond()}.
     *
     * @throws VerifyException on any refusal, carrying a {@link Reason}
     */
    public Map<String, Object> verify(String token, long nowEpochSeconds) throws VerifyException {
        if (token == null || token.length() > MAX_TOKEN_BYTES) {
            throw new VerifyException(Reason.MALFORMED_STRUCTURE, "absent or larger than " + MAX_TOKEN_BYTES);
        }
        // Split with a limit of -1 so trailing empty segments are KEPT: `h.p.` must be seen as
        // three segments with an empty signature (that is exactly the `alg: none` shape), not as
        // two. Java's default split would drop it and produce the wrong refusal.
        String[] segments = token.split("\\.", -1);
        if (segments.length != 3) {
            throw new VerifyException(Reason.MALFORMED_STRUCTURE, "a JWS has three segments, found " + segments.length);
        }

        byte[] headerBytes = decode(segments[0]);
        Map<String, Object> header = readObject(headerBytes, Reason.HEADER_MALFORMED, "header");

        if (header.containsKey("crit")) {
            // RFC 7515 4.1.11: an extension a verifier does not understand must be REFUSED, not
            // ignored, because its whole purpose is to change how the token is to be read. This
            // verifier implements no extensions, so any `crit` at all is unknown.
            throw new VerifyException(Reason.UNKNOWN_CRIT, "the header names a crit extension this verifier does not implement");
        }
        if (header.containsKey("jwk") || header.containsKey("jku") || header.containsKey("x5u") || header.containsKey("x5c")) {
            // A token that carries or points at its own key is asking to be verified against the
            // attacker's key. Refused structurally, BEFORE any signature is checked, so it stays
            // refused even against a signature that would have validated.
            throw new VerifyException(Reason.EMBEDDED_KEY_INJECTION, "the header carries or points at its own key");
        }
        if (!(header.get("alg") instanceof String alg)) {
            throw new VerifyException(Reason.HEADER_MALFORMED, "the header has no `alg` string");
        }
        if ("none".equals(alg)) {
            throw new VerifyException(Reason.ALG_NONE, "an unsigned token never verifies");
        }
        if (!algorithms.contains(alg)) {
            throw new VerifyException(Reason.ALG_NOT_ALLOWED, alg + " is not published by this issuer");
        }

        String kid = header.get("kid") instanceof String value ? value : null;
        TrustedKey key = resolve(kid, alg);

        byte[] signature = decode(segments[2]);
        byte[] signed = (segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII);
        if (!signatureVerifies(alg, key, signed, signature)) {
            throw new VerifyException(Reason.SIGNATURE_INVALID, "the signature does not verify under " + key);
        }

        // Everything below here is reading a token whose signature we have checked. Nothing above
        // may move below, and nothing below may move above.
        Map<String, Object> claims = readObject(decode(segments[1]), Reason.CLAIMS_MALFORMED, "claims");

        if (!(claims.get("iss") instanceof String tokenIssuer) || !issuer.equals(tokenIssuer)) {
            // Compared EXACTLY: two environments of one deployment differ only by a path segment,
            // so a prefix or "starts with" comparison lets a sibling environment's token in.
            throw new VerifyException(Reason.ISSUER_MISMATCH, "iss is not " + issuer);
        }
        if (!audienceMatches(claims.get("aud"))) {
            throw new VerifyException(Reason.AUDIENCE_MISMATCH, "aud does not include " + audience);
        }
        if (!(claims.get("exp") instanceof Double exp)) {
            // A token with no expiry is a token that never expires. Refused rather than accepted
            // with a shrug.
            throw new VerifyException(Reason.CLAIMS_MALFORMED, "exp is absent or not a number");
        }
        if (nowEpochSeconds > exp.longValue() + skewSeconds) {
            throw new VerifyException(Reason.EXPIRED, "exp passed at " + exp.longValue());
        }
        if (claims.containsKey("nbf")) {
            // Present but not a number is MALFORMED, not absent. Treating it as absent would mean
            // `"nbf": "tomorrow"` silently disables the check it was written to perform.
            if (!(claims.get("nbf") instanceof Double nbf)) {
                throw new VerifyException(Reason.CLAIMS_MALFORMED, "nbf is present but not a number");
            }
            if (nowEpochSeconds < nbf.longValue() - skewSeconds) {
                throw new VerifyException(Reason.NOT_YET_VALID, "nbf arrives at " + nbf.longValue());
            }
        }
        return claims;
    }

    /**
     * Find the trusted key named by {@code kid} that can carry {@code alg}.
     *
     * <p>An absent {@code kid} is allowed only when exactly one trusted key fits the algorithm.
     * With several, guessing would mean trying each in turn, which quietly converts "the issuer
     * rotated" into "any published key will do".
     */
    private TrustedKey resolve(String kid, String alg) throws VerifyException {
        List<TrustedKey> named =
                kid == null ? keys : keys.stream().filter(candidate -> kid.equals(candidate.kid())).toList();
        if (named.isEmpty()) {
            throw new VerifyException(Reason.UNKNOWN_KID, "no published key has kid " + kid);
        }
        List<TrustedKey> usable = named.stream().filter(candidate -> candidate.supports(alg)).toList();
        if (usable.isEmpty()) {
            throw new VerifyException(Reason.KEY_TYPE_MISMATCH, "the key named " + kid + " cannot carry " + alg);
        }
        if (usable.size() > 1) {
            throw new VerifyException(Reason.UNKNOWN_KID, "several published keys match kid " + kid);
        }
        return usable.get(0);
    }

    private static boolean signatureVerifies(String alg, TrustedKey key, byte[] signed, byte[] signature) {
        try {
            // "inP1363Format" takes the raw r||s pair JWS uses. The plain "SHA256withECDSA" name
            // wants DER, and hand-rolling that conversion is a classic source of parser bugs in
            // JOSE libraries; the JDK has shipped the right variant since Java 9.
            String jcaName = switch (alg) {
                case "EdDSA" -> "Ed25519";
                case "ES256" -> "SHA256withECDSAinP1363Format";
                case "RS256" -> "SHA256withRSA";
                default -> throw new IllegalStateException("unreachable: " + alg + " passed the allow-list");
            };
            Signature verifier = Signature.getInstance(jcaName);
            verifier.initVerify(key.key());
            verifier.update(signed);
            return verifier.verify(signature);
        } catch (Exception refused) {
            // A malformed signature makes the JCA throw rather than return false (an ECDSA pair
            // of the wrong length, for one). That is a failed verification, not a crash.
            return false;
        }
    }

    private boolean audienceMatches(Object aud) {
        if (aud instanceof String single) {
            return audience.equals(single);
        }
        if (aud instanceof List<?> many) {
            // RFC 7519 4.1.3: aud may be an array, and MEMBERSHIP is what counts. Not the first
            // element, and not the whole array rendered as a string.
            return many.contains(audience);
        }
        return false;
    }

    /** Decode one unpadded base64url segment. */
    private static byte[] decode(String segment) throws VerifyException {
        // RFC 7515 2 requires base64url with the padding REMOVED. Java's URL decoder would also
        // accept padded input, so the characters are checked here: accepting `=` means two
        // different encodings of one token, which is how signature-stripping tricks start.
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            boolean allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!allowed) {
                throw new VerifyException(Reason.BASE64_MALFORMED, "a segment is not unpadded base64url");
            }
        }
        try {
            return Base64.getUrlDecoder().decode(segment);
        } catch (IllegalArgumentException malformed) {
            throw new VerifyException(Reason.BASE64_MALFORMED, "a segment is not base64url");
        }
    }

    private static Map<String, Object> readObject(byte[] bytes, Reason reason, String what) throws VerifyException {
        try {
            Object parsed = Json.parse(new String(bytes, StandardCharsets.UTF_8));
            if (parsed instanceof Map<?, ?> members) {
                @SuppressWarnings("unchecked")
                Map<String, Object> typed = (Map<String, Object>) members;
                return typed;
            }
            throw new VerifyException(reason, "the " + what + " is not a JSON object");
        } catch (RuntimeException malformed) {
            // RuntimeException, not IllegalArgumentException. Everything reaching this point is
            // attacker-controlled, and a parser defect must surface as a REFUSED TOKEN rather than
            // as an unchecked exception the caller never declared. Json is bounds-checked so this
            // should be unreachable; a backstop whose whole job is the case you did not think of
            // is worth the four lines. VerifyException is checked, so it passes through untouched.
            throw new VerifyException(reason, "the " + what + " is not JSON");
        }
    }
}
