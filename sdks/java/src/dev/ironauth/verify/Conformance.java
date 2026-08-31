// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import dev.ironauth.verify.IronAuthVerifier.Reason;
import dev.ironauth.verify.IronAuthVerifier.VerifyException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The Java verifier against the cross-language conformance corpus (issue #118).
 *
 * <p>Run as {@code java dev.ironauth.verify.Conformance <path to verify-vectors.json>}. It exits
 * non-zero and names every disagreement; there is no test framework, because adding JUnit to
 * prove an artifact needs no dependencies would be an odd way to make the point.
 *
 * <h2>What this run adds that the others could not</h2>
 *
 * <p>The corpus is judged by six verifiers. Until now every one of them had a capability gap:
 * the Rust verifier has no P-256 key type and refuses the ES256 vector on the allow-list rather
 * than verifying it. <strong>The JDK does all three algorithms, so this is the first
 * implementation that verifies every accepted vector in the corpus</strong> -- Ed25519, P-256 and
 * RSA -- and the first for which {@code alg_not_published_by_the_issuer} tests what it was written
 * to test.
 *
 * <p>That vector is the SAME token as {@code valid_es256}, judged against an issuer publishing
 * EdDSA only. For a verifier that cannot do ES256 at all, passing it proves nothing: it would
 * refuse that token whatever the allow-list said. Here the two vectors differ in exactly one
 * respect -- the published algorithm set -- and the outcomes differ with them, which is the
 * only arrangement in which "the allow-list is the issuer's metadata, never the token header"
 * is actually measured.
 *
 * <h2>The reason mapping is the interoperability contract</h2>
 *
 * <p>The implementations do not share an error vocabulary: the TypeScript core reports eight
 * coarse reasons, this verifier reports fifteen. The mapping is MANY-TO-ONE and explicit, so a
 * refusal that is right for a more precise reason passes and a refusal for the WRONG reason does
 * not. Widening it is how a conformance suite stops meaning anything, so each widening below is
 * named and argued.
 */
public final class Conformance {

    private Conformance() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: Conformance <path to verify-vectors.json>");
            System.exit(2);
        }
        Map<String, Object> corpus = object(Json.parse(Files.readString(Path.of(args[0]))));

        long now = ((Double) corpus.get("now")).longValue();
        String issuer = (String) corpus.get("issuer");
        String audience = (String) corpus.get("audience");
        List<TrustedKey> keys = TrustedKey.fromJwks(jwksText(corpus));
        Set<String> published = strings(corpus.get("algorithms"));
        Set<String> eddsaOnly = strings(corpus.get("algorithmsEddsaOnly"));

        List<Object> cases = list(corpus.get("cases"));
        List<String> failures = new ArrayList<>();
        Set<String> acceptedAlgorithms = new LinkedHashSet<>();
        int accepts = 0;
        int refusals = 0;

        for (Object element : cases) {
            Map<String, Object> vector = object(element);
            String name = (String) vector.get("name");
            String token = (String) vector.get("token");
            String expect = (String) vector.get("expect");
            String why = (String) vector.get("why");

            // The allow-list is the ISSUER's published set. One vector is judged against an
            // EdDSA-only issuer, which is what turns it into a test of the allow-list rather than
            // of whether ES256 happens to be implemented.
            Set<String> algorithms = "alg_not_published_by_the_issuer".equals(name) ? eddsaOnly : published;
            IronAuthVerifier verifier = new IronAuthVerifier(algorithms, keys, issuer, audience, 0);

            if ("accept".equals(expect)) {
                accepts++;
                try {
                    Map<String, Object> claims = verifier.verify(token, now);
                    if (!issuer.equals(claims.get("iss"))) {
                        failures.add(name + ": verified but returned iss=" + claims.get("iss"));
                    }
                    acceptedAlgorithms.add(algorithmOf(token));
                } catch (VerifyException refused) {
                    failures.add(name + " must verify (" + why + "), refused as " + refused.reason());
                }
                continue;
            }

            refusals++;
            try {
                verifier.verify(token, now);
                failures.add(name + " must be refused as " + expect + " (" + why + "), but it verified");
            } catch (VerifyException refused) {
                Set<Reason> permitted = acceptable(name, expect);
                if (permitted.isEmpty()) {
                    failures.add("the corpus expects `" + expect + "`, which this mapping does not cover");
                } else if (!permitted.contains(refused.reason())) {
                    failures.add(name + ": the corpus expects `" + expect + "` and Java refused it as "
                            + refused.reason() + ", which is not among " + permitted + ". " + why);
                }
            }
        }

        // A conformance suite that iterates a list is exactly as good as the list, and the corpus
        // is the artifact someone weakens under deadline. These floors are not style: deleting
        // the alg_none vector would otherwise turn every verifier green on an unsigned token.
        if (cases.size() < 16) {
            failures.add("the corpus shrank to " + cases.size() + " vectors");
        }
        if (refusals < 10) {
            failures.add("only " + refusals + " refusal vectors reached the verifier");
        }
        if (accepts < 3) {
            failures.add("only " + accepts + " accepted vectors, so a refuse-everything verifier would pass");
        }
        // The claim this artifact makes over the others: all three algorithms actually verified.
        // Without this a future change that broke RSA would leave the suite green on Ed25519.
        for (String required : List.of("EdDSA", "ES256", "RS256")) {
            if (!acceptedAlgorithms.contains(required)) {
                failures.add("no accepted vector was verified with " + required
                        + "; the Java artifact claims all three and this run proves " + acceptedAlgorithms);
            }
        }
        // The corpus's own refusal vocabulary must stay covered, checked against the corpus
        // rather than against this file, so a NEW expectation fails here instead of being
        // silently mapped to something adjacent.
        Set<String> expectations = new HashSet<>();
        for (Object element : cases) {
            String expect = (String) object(element).get("expect");
            if (!"accept".equals(expect)) {
                expectations.add(expect);
            }
        }
        for (String required : List.of(
                "algorithm_not_allowed", "bad_signature", "unknown_key", "wrong_issuer",
                "wrong_audience", "expired", "not_yet_valid", "malformed")) {
            if (!expectations.contains(required)) {
                failures.add("the corpus no longer covers " + required);
            }
        }

        if (!failures.isEmpty()) {
            System.err.println("FAIL: the Java verifier disagrees with the corpus");
            failures.forEach(failure -> System.err.println("  - " + failure));
            System.exit(1);
        }
        System.out.println("java conformance: " + cases.size() + " vectors ("
                + accepts + " accepted across " + acceptedAlgorithms + ", " + refusals + " refused) OK");
    }

    /**
     * The verifier reasons that satisfy one corpus expectation.
     *
     * <p>Returns an empty set for an expectation the mapping does not know, which the caller
     * reports as a failure rather than treating as "nothing to check".
     */
    private static Set<Reason> acceptable(String name, String expect) {
        // ONE per-vector widening, named and scoped.
        //
        // The corpus expects `bad_signature` for the embedded-JWK injection, because the
        // TypeScript core resolves the key from the published set, ignores the header's `jwk`,
        // and the attacker's signature then fails against the real key. This verifier refuses it
        // STRUCTURALLY, before any signature is checked, because a `jwk` in a header verified
        // against a trusted key set has no legitimate purpose.
        //
        // That refusal is strictly stronger: it holds even against a signature that WOULD have
        // validated. Widening `bad_signature` everywhere to accept EMBEDDED_KEY_INJECTION would
        // be the lazy version and would let a key-injection refusal satisfy a tampered-payload
        // expectation, so the widening lives here, on the one vector it describes.
        if ("embedded_jwk_key_injection".equals(name)) {
            return Set.of(Reason.EMBEDDED_KEY_INJECTION, Reason.SIGNATURE_INVALID);
        }
        return switch (expect) {
            case "malformed" -> Set.of(
                    Reason.MALFORMED_STRUCTURE,
                    Reason.BASE64_MALFORMED,
                    Reason.HEADER_MALFORMED,
                    Reason.CLAIMS_MALFORMED,
                    Reason.UNKNOWN_CRIT);
            // `alg: none` has its own reason here, which is more precise than the corpus's
            // coarse name and is the same refusal.
            case "algorithm_not_allowed" -> Set.of(Reason.ALG_NONE, Reason.ALG_NOT_ALLOWED, Reason.KEY_TYPE_MISMATCH);
            case "unknown_key" -> Set.of(Reason.UNKNOWN_KID);
            case "bad_signature" -> Set.of(Reason.SIGNATURE_INVALID);
            case "wrong_issuer" -> Set.of(Reason.ISSUER_MISMATCH);
            case "wrong_audience" -> Set.of(Reason.AUDIENCE_MISMATCH);
            case "expired" -> Set.of(Reason.EXPIRED);
            case "not_yet_valid" -> Set.of(Reason.NOT_YET_VALID);
            default -> Set.of();
        };
    }

    /** The `alg` a token names, for reporting which algorithms actually verified. */
    private static String algorithmOf(String token) {
        String[] segments = token.split("\\.", -1);
        byte[] header = java.util.Base64.getUrlDecoder().decode(segments[0]);
        return (String) object(Json.parse(new String(header, java.nio.charset.StandardCharsets.UTF_8))).get("alg");
    }

    /**
     * Re-render the corpus's parsed JWKS as JSON for {@link TrustedKey#fromJwks}.
     *
     * <p>The alternative is a second entry point taking an already-parsed map, which would mean
     * the conformance run exercised a code path no real caller uses. A caller has a JWKS
     * DOCUMENT, so the suite hands the decoder a document.
     */
    private static String jwksText(Map<String, Object> corpus) {
        StringBuilder out = new StringBuilder("{\"keys\":[");
        List<Object> keys = list(object(corpus.get("jwks")).get("keys"));
        for (int i = 0; i < keys.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append('{');
            Map<String, Object> jwk = object(keys.get(i));
            boolean first = true;
            for (Map.Entry<String, Object> member : jwk.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                // Every JWK member the corpus uses is a string; a non-string would be a corpus
                // change this rendering cannot express, so it fails loudly rather than emitting
                // something that parses to the wrong key.
                if (!(member.getValue() instanceof String value)) {
                    throw new IllegalStateException("the JWK member " + member.getKey() + " is not a string");
                }
                out.append('"').append(member.getKey()).append("\":\"").append(value).append('"');
            }
            out.append('}');
        }
        return out.append("]}").toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value) {
        return (List<Object>) value;
    }

    private static Set<String> strings(Object value) {
        Set<String> out = new LinkedHashSet<>();
        for (Object element : list(value)) {
            out.add((String) element);
        }
        return out;
    }
}
