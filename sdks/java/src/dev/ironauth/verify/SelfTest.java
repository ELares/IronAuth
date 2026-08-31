// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import dev.ironauth.verify.IronAuthVerifier.Reason;
import dev.ironauth.verify.IronAuthVerifier.VerifyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The properties the shared corpus CANNOT express (issue #118).
 *
 * <p>The corpus is a fixed list of tokens signed by fixed keys, so every property it can state is
 * of the form "this exact token gets this answer". Three things this verifier claims are not of
 * that form, and each was chosen because a mutation run showed the corpus could not see it:
 *
 * <ul>
 *   <li><strong>Key injection is refused BEFORE the signature is checked.</strong> The corpus's
 *       {@code embedded_jwk_key_injection} vector carries an attacker's key and an attacker's
 *       signature, so a verifier with no structural check still refuses it -- the signature fails
 *       against the real key. Deleting the check keeps the corpus green. The claim that the
 *       refusal is <em>structural</em> therefore needs a token whose signature is genuinely VALID,
 *       which the corpus has no key to mint.
 *   <li><strong>Size is bounded before decoding.</strong> No fixed corpus contains a 9 KiB token.
 *   <li><strong>A token with no expiry never verifies.</strong> Every corpus vector has {@code exp}.
 * </ul>
 *
 * <p>Run as {@code java dev.ironauth.verify.SelfTest}; it exits non-zero and names each failure.
 */
public final class SelfTest {

    private SelfTest() {}

    private static final String ISSUER = "https://issuer.example/t/tnt_self/e/env_self";
    private static final String AUDIENCE = "cli_self";
    private static final long NOW = 1_800_000_000L;

    private static final List<String> FAILURES = new ArrayList<>();

    /**
     * How many properties actually ran.
     *
     * <p>Counted rather than written down. A hand-written total in the success line is a claim
     * about this file made somewhere else in it, and it goes stale the first time someone
     * comments an assertion out -- leaving a green run reporting a number that was true once.
     */
    private static int checked;

    public static void main(String[] args) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        TrustedKey trusted = new TrustedKey("self-1", "OKP", pair.getPublic());
        IronAuthVerifier verifier =
                new IronAuthVerifier(Set.of("EdDSA"), List.of(trusted), ISSUER, AUDIENCE, 0);

        String claims = "{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + AUDIENCE
                + "\",\"sub\":\"usr_self\",\"exp\":" + (NOW + 3600) + "}";

        // THE CONTROL, and it is the whole reason the next assertion means anything. It varies
        // from the injection token in exactly ONE respect: the header. Without it, a refusal
        // below could be caused by a mint this test got wrong, and would look identical.
        String honest = Fixtures.mint(pair, "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"self-1\"}", claims);
        accepts(verifier, honest, "a correctly minted token verifies (the control for the next case)");

        // The property the corpus cannot reach: a VALID signature by a PUBLISHED key, with a
        // `jwk` header bolted on. A verifier that merely ignores the embedded key accepts this,
        // because the signature really does verify. Only a structural refusal catches it.
        String injected = Fixtures.mint(
                pair,
                "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"self-1\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"F83SEmSVgKMBLYCoZfCPDHVGDGVoXVfyxRZsGnPPYQE\"}}",
                claims);
        refuses(verifier, injected, Reason.EMBEDDED_KEY_INJECTION,
                "a header carrying its own key is refused even when the signature is VALID");

        // The same, for the indirect forms. `jku` and `x5u` point at a key instead of carrying
        // one, which is the same attack with a fetch in the middle.
        for (String member : List.of("jku\":\"https://attacker.example/keys", "x5u\":\"https://attacker.example/chain")) {
            String header = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"self-1\",\"" + member + "\"}";
            refuses(verifier, Fixtures.mint(pair, header, claims), Reason.EMBEDDED_KEY_INJECTION,
                    "a header pointing AT a key is refused too, not only one carrying it");
        }

        // Bounded before decoding. A validly signed token padded past the cap must still be
        // refused on size, so the bound is not merely documented.
        String oversize = honest + "A".repeat(IronAuthVerifier.MAX_TOKEN_BYTES);
        refuses(verifier, oversize, Reason.MALFORMED_STRUCTURE, "an oversized token is refused before decoding");

        // Padding is not accepted: one token must have exactly one encoding.
        refuses(verifier, honest.substring(0, honest.lastIndexOf('.')) + ".AA==",
                Reason.BASE64_MALFORMED, "a PADDED segment is refused, so a token has one encoding");

        // A token with no expiry is a token that never expires.
        String noExpiry = Fixtures.mint(
                pair,
                "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"self-1\"}",
                "{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + AUDIENCE + "\",\"sub\":\"usr_self\"}");
        refuses(verifier, noExpiry, Reason.CLAIMS_MALFORMED, "a token with no exp never verifies");

        // NO INPUT ESCAPES AS AN UNCHECKED EXCEPTION.
        //
        // This is the property a review found broken. `verify` declares VerifyException, so a
        // caller writes one catch and believes it covers every bad token. Two inputs made the
        // hand-written JSON reader throw StringIndexOutOfBoundsException instead -- not an
        // IllegalArgumentException, so it sailed past the verifier's catch and out of the method.
        // In a servlet that is a 500 where a 401 belonged: the wrong status, the wrong alert, and
        // a stack trace in the log for what is simply an invalid token.
        //
        // The corpus cannot reach this. Its malformed vectors are malformed BASE64; these are
        // valid base64 carrying hostile JSON, and each one is a shape the reader has to bound.
        char backslash = (char) 92;
        String head = "{\"alg\":\"EdDSA\",\"kid\":\"self-1\",\"x\":\"";
        List<String> hostileHeaders = List.of(
                head + backslash,                          // input ends inside an escape
                head + backslash + "u12",                  // input ends inside a hex escape
                head + backslash + "uZZZZ" + "\"}",         // a hex escape with non-hex digits
                head + backslash + "q\"}",                  // an escape that does not exist
                "[".repeat(6100),                          // nesting deep enough to blow the stack
                "{\"a\":".repeat(6100) + "1");             // the same, through objects
        for (String hostile : hostileHeaders) {
            String token = Fixtures.b64(hostile.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + ".e30.AA";
            checked++;
            try {
                verifier.verify(token, NOW);
                FAILURES.add("a hostile header VERIFIED: " + summarise(hostile));
            } catch (VerifyException expected) {
                // A refusal is the whole point; which refusal is not, since these are all garbage.
            } catch (Throwable escaped) {
                FAILURES.add("a hostile header threw " + escaped.getClass().getName()
                        + " out of verify(), which callers do not catch: " + summarise(hostile));
            }
        }

        // AND THE SAME PROPERTY ONE LAYER DOWN, on the parser itself.
        //
        // The loop above passes with EITHER the reader's bounds checks OR the verifier's
        // RuntimeException backstop in place, because each masks the other: a mutation run
        // removing just one left the suite green. Two layers is the right design here, but it
        // means neither is measured by an end-to-end test alone.
        //
        // So this asserts the reader's own contract directly, which only the bounds checks can
        // satisfy: `Json.parse` throws IllegalArgumentException and NOTHING else. The backstop
        // cannot make this pass, so the two layers now have one test each.
        for (String hostile : hostileHeaders) {
            checked++;
            try {
                Json.parse(hostile);
                FAILURES.add("Json.parse accepted hostile input: " + summarise(hostile));
            } catch (IllegalArgumentException expected) {
                // The declared failure mode.
            } catch (Throwable escaped) {
                FAILURES.add("Json.parse threw " + escaped.getClass().getName()
                        + ", which is outside its contract: " + summarise(hostile));
            }
        }

        // `nbf` present but not a number must be MALFORMED, not treated as absent: otherwise
        // `"nbf": "tomorrow"` silently disables the check it was written to perform.
        refuses(verifier, Fixtures.mint(pair, "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"self-1\"}",
                        "{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + AUDIENCE + "\",\"exp\":" + (NOW + 3600)
                                + ",\"nbf\":\"tomorrow\"}"),
                Reason.CLAIMS_MALFORMED, "a non-numeric nbf is malformed, not absent");

        // An empty allow-list reads as "allow nothing" and behaves as a silent outage, so it is
        // refused at construction rather than at the first request.
        try {
            checked++;
            new IronAuthVerifier(Set.of(), List.of(trusted), ISSUER, AUDIENCE, 0);
            FAILURES.add("an empty algorithm allow-list was accepted at construction");
        } catch (IllegalArgumentException expected) {
            // as intended
        }

        // The Ed25519 JWK encoding round-trips. The corpus proves DECODING works; this proves the
        // parity bit is handled in both directions, which is the half a fixed corpus cannot see.
        String x = Fixtures.encodeEd25519((EdECPublicKey) pair.getPublic());
        String jwks = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + x + "\",\"kid\":\"self-1\"}]}";
        List<TrustedKey> decoded = TrustedKey.fromJwks(jwks);
        checked++;
        if (decoded.size() != 1 || !decoded.get(0).key().equals(pair.getPublic())) {
            FAILURES.add("an Ed25519 key did not survive a JWK round trip: " + decoded);
        }

        if (!FAILURES.isEmpty()) {
            System.err.println("FAIL: the Java verifier does not hold its own claims");
            FAILURES.forEach(failure -> System.err.println("  - " + failure));
            System.exit(1);
        }
        // A floor, so commenting assertions out fails here instead of reporting a smaller number
        // in a green run. It is a floor and not an equality: adding a property should not break it.
        if (checked < 22) {
            System.err.println("FAIL: only " + checked + " properties ran; this suite is its list");
            System.exit(1);
        }
        System.out.println("java self-test: " + checked + " properties the corpus cannot express OK");
    }

    /** A short, log-safe rendering of a hostile input, so a failure names it without a wall of text. */
    private static String summarise(String hostile) {
        String head = hostile.length() > 40 ? hostile.substring(0, 40) + "..." : hostile;
        return "(" + hostile.length() + " chars) " + head;
    }

    private static void accepts(IronAuthVerifier verifier, String token, String why) {
        checked++;
        try {
            verifier.verify(token, NOW);
        } catch (VerifyException refused) {
            FAILURES.add(why + " -- refused as " + refused.reason());
        }
    }

    private static void refuses(IronAuthVerifier verifier, String token, Reason expected, String why) {
        checked++;
        try {
            verifier.verify(token, NOW);
            FAILURES.add(why + " -- but it VERIFIED");
        } catch (VerifyException refused) {
            if (refused.reason() != expected) {
                FAILURES.add(why + " -- expected " + expected + ", got " + refused.reason());
            }
        }
    }

}
