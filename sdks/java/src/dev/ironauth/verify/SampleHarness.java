// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Runs {@link Sample} end to end against a loopback issuer (issue #118).
 *
 * <p>{@link Sample} is the artifact criterion 4 actually asks for: a Java sample that verifies an
 * IronAuth token out of the box. A sample nobody executes is the failure mode worth avoiding
 * here -- it compiles, it reads correctly, and it is wrong. So this stands up a real HTTP server
 * on the loopback interface publishing a real discovery document and a real JWK Set, mints a
 * real token, and drives the sample's whole path: discovery, {@code jwks_uri}, key decode,
 * algorithm allow-list, verification.
 *
 * <p>It uses only {@code com.sun.net.httpserver}, which ships with the JDK, so the no-dependency
 * claim survives its own test. Run as {@code java dev.ironauth.verify.SampleHarness}.
 */
public final class SampleHarness {

    private SampleHarness() {}

    private static final List<String> FAILURES = new ArrayList<>();
    private static int checked;

    /** The algorithms the fake issuer advertises; a test mutates this to include {@code none}. */
    private static volatile String advertisedAlgorithms = "[\"EdDSA\"]";

    /** The issuer name the discovery document claims, which is not always the one being asked for. */
    private static volatile String advertisedIssuer;

    /** When set, discovery points at a key set far larger than the sample will read. */
    private static volatile boolean oversizeJwks;

    /** When set, discovery answers 302 to a document that names the RIGHT issuer and wrong keys. */
    private static volatile boolean redirectDiscovery;

    public static void main(String[] args) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String x = Fixtures.encodeEd25519((EdECPublicKey) pair.getPublic());
        // A second key, published only behind the redirect, so following it changes the answer.
        String elsewhereX = Fixtures.encodeEd25519(
                (EdECPublicKey) KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic());

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        advertisedIssuer = base;

        server.createContext("/.well-known/openid-configuration", exchange -> {
            if (redirectDiscovery) {
                exchange.getResponseHeaders().add("location", base + "/elsewhere-discovery");
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
                return;
            }
            respond(exchange,
                    "{\"issuer\":\"" + advertisedIssuer + "\",\"jwks_uri\":\"" + base
                            + (oversizeJwks ? "/huge-jwks" : "/jwks") + "\","
                            + "\"id_token_signing_alg_values_supported\":" + advertisedAlgorithms + "}");
        });
        // The redirect target names the CORRECT issuer and points at a DIFFERENT key set. That
        // combination is the point: the issuer check cannot save you here, so only the decision
        // not to follow the redirect does.
        // Two megabytes of valid JSON, over the sample's one-megabyte ceiling.
        server.createContext("/huge-jwks", exchange -> respond(exchange,
                "{\"keys\":[],\"padding\":\"" + "A".repeat(2 << 20) + "\"}"));
        server.createContext("/elsewhere-discovery", exchange -> respond(exchange,
                "{\"issuer\":\"" + base + "\",\"jwks_uri\":\"" + base + "/elsewhere-jwks\","
                        + "\"id_token_signing_alg_values_supported\":[\"EdDSA\"]}"));
        server.createContext("/elsewhere-jwks", exchange -> respond(exchange,
                "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + elsewhereX + "\",\"kid\":\"sample-1\"}]}"));
        server.createContext("/jwks", exchange -> respond(exchange,
                "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + x + "\",\"kid\":\"sample-1\"}]}"));
        server.start();

        try {
            long now = Instant.now().getEpochSecond();
            String claims = "{\"iss\":\"" + base + "\",\"aud\":\"cli_sample\",\"sub\":\"usr_sample\",\"exp\":"
                    + (now + 3600) + ",\"nbf\":" + (now - 60) + "}";
            String header = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"sample-1\"}";
            String token = Fixtures.mint(pair, header, claims);

            // THE SAMPLE ACTUALLY RUNS. Discovery, jwks_uri, key decode, verification.
            check("the sample verifies a live Ed25519 token end to end", () -> {
                Map<String, Object> verified = Sample.verify(base, "cli_sample", token);
                return "usr_sample".equals(verified.get("sub")) ? null : "sub was " + verified.get("sub");
            });

            // A tampered token over the same live path, so the harness cannot pass by never
            // reaching the verifier at all.
            String tampered = token.substring(0, token.length() - 4) + "AAAA";
            check("a tampered token is refused over the same path", () -> {
                try {
                    Sample.verify(base, "cli_sample", tampered);
                    return "it verified";
                } catch (IronAuthVerifier.VerifyException refused) {
                    return refused.reason() == IronAuthVerifier.Reason.SIGNATURE_INVALID
                            ? null : "refused as " + refused.reason();
                }
            });

            // An issuer that advertises `none` must not talk the sample into accepting an
            // unsigned token. Note WHERE that is enforced: the refusal below is ALG_NONE, which
            // the verifier raises by name, so this passes even with the sample's own
            // `algorithms.remove("none")` deleted. It is still worth running -- it is the
            // end-to-end statement that a compromised issuer gets nowhere -- but it does not
            // measure that one line, and a mutation run said so.
            advertisedAlgorithms = "[\"none\",\"EdDSA\"]";
            String unsigned = Fixtures.b64("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8))
                    + "." + Fixtures.b64(claims.getBytes(StandardCharsets.UTF_8)) + ".";
            check("an issuer advertising `none` still cannot get an unsigned token accepted", () -> {
                try {
                    Sample.verify(base, "cli_sample", unsigned);
                    return "it verified";
                } catch (IronAuthVerifier.VerifyException refused) {
                    return refused.reason() == IronAuthVerifier.Reason.ALG_NONE
                            ? null : "refused as " + refused.reason();
                }
            });
            // And the control: with `none` advertised, a GOOD token still verifies. Without this,
            // the assertion above would also pass if advertising `none` broke the sample outright.
            check("with `none` advertised, an honest token still verifies", () -> {
                Map<String, Object> verified = Sample.verify(base, "cli_sample", token);
                return "usr_sample".equals(verified.get("sub")) ? null : "sub was " + verified.get("sub");
            });
            // THE ALLOW-LIST REALLY COMES FROM DISCOVERY. An issuer publishing only RS256 must
            // refuse the honest EdDSA token, on the allow-list and not on the signature. Without
            // this, replacing the discovered list with a hard-coded superset would pass every
            // other check here, and the claim that the issuer decides would be decoration.
            advertisedAlgorithms = "[\"RS256\"]";
            check("an algorithm the issuer does not publish is refused on the allow-list", () -> {
                try {
                    Sample.verify(base, "cli_sample", token);
                    return "it verified";
                } catch (IronAuthVerifier.VerifyException refused) {
                    return refused.reason() == IronAuthVerifier.Reason.ALG_NOT_ALLOWED
                            ? null : "refused as " + refused.reason();
                }
            });
            advertisedAlgorithms = "[\"EdDSA\"]";

            // Discovery that names a different issuer must be refused. Otherwise pointing the
            // sample at any URL yields a document naming an attacker-chosen issuer and a key set
            // to match, and every later comparison passes against that name.
            advertisedIssuer = "https://attacker.example";
            check("discovery naming a different issuer is refused", () -> {
                try {
                    Sample.verify(base, "cli_sample", token);
                    return "it verified";
                } catch (IllegalStateException expected) {
                    return null;
                }
            });
            advertisedIssuer = base;

            // The document size ceiling is REAL, not a length check after the fact: a body is read
            // in bounded chunks and refused the moment it passes the limit. Measured here because
            // a bound nothing ever exceeds is indistinguishable from a bound that does not work.
            oversizeJwks = true;
            check("an oversized key set is refused rather than buffered", () -> {
                try {
                    Sample.verify(base, "cli_sample", token);
                    return "it verified";
                } catch (java.io.IOException expected) {
                    return expected.getMessage().contains("more than") ? null : "failed with " + expected.getMessage();
                }
            });
            oversizeJwks = false;

            // A redirect on discovery is an invitation to fetch someone else's keys, so the
            // client is built with Redirect.NEVER. Following it here would reach a document
            // naming the right issuer and the wrong keys, which every later check would accept.
            // Not following makes the 302 itself the error, and THAT is what this pins.
            redirectDiscovery = true;
            check("a redirect on discovery is not followed", () -> {
                try {
                    Sample.verify(base, "cli_sample", token);
                    return "it verified";
                } catch (java.io.IOException expected) {
                    return expected.getMessage().contains("302") ? null : "failed with " + expected.getMessage();
                }
            });
            redirectDiscovery = false;

            // Plaintext off the loopback interface is refused before any request is made, so this
            // needs no network and cannot flake.
            check("plaintext discovery off loopback is refused", () -> {
                try {
                    Sample.verify("http://issuer.example", "cli_sample", token);
                    return "it verified";
                } catch (IllegalStateException expected) {
                    return null;
                }
            });

            if (checked < 9) {
                FAILURES.add("only " + checked + " checks ran; this harness is its list");
            }
        } finally {
            server.stop(0);
        }

        if (!FAILURES.isEmpty()) {
            System.err.println("FAIL: the Java sample does not hold up end to end");
            FAILURES.forEach(failure -> System.err.println("  - " + failure));
            System.exit(1);
        }
        System.out.println("java sample harness: " + checked + " end-to-end checks against a live issuer OK");
    }

    /** Run one check; the supplier returns null on success or a description of what went wrong. */
    private static void check(String what, ThrowingSupplier check) {
        checked++;
        try {
            String problem = check.get();
            if (problem != null) {
                FAILURES.add(what + " -- " + problem);
            }
        } catch (Exception unexpected) {
            FAILURES.add(what + " -- threw " + unexpected);
        }
    }

    /** A {@link Supplier} that may throw, since every one of these does I/O or crypto. */
    private interface ThrowingSupplier {
        String get() throws Exception;
    }

    private static void respond(HttpExchange exchange, String body) throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("content-type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
